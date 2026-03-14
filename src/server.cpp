#include <algorithm>
#include <unistd.h>
#include <thread>
#include <memory>

#include <logger.h>
#include <dnasbypass/client.h>

#include <server.h>

Server::Server(Server::Type type)
{	
	int port = 443;
	int opt = 10; // After 10 seconds time out socket
	
	std::map<std::string, std::string> cert_key_files = {
	//	{ "../data/ssl/cert-eu.pem", "../data/ssl/cert-eu-key.pem" },
		{ "../data/ssl/cert-us.pem", "../data/ssl/cert-us-key.pem" },
	//	{ "../data/ssl/cert-jp.pem", "../data/ssl/cert-jp-key.pem" },
	};
	
	this->_InitSSL(cert_key_files, "../data/ssl/ca-cert.pem");
	
	this->_type = type;
	
	if ((this->_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		Logger::error("Server::Server() at socket");
		exit(EXIT_FAILURE);
	}
	
	if (setsockopt(this->_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
	{
		Logger::error("Server::Server() at setsockopt");
		exit(EXIT_FAILURE);
	}

	this->_address.sin_family = AF_INET;
	this->_address.sin_addr.s_addr = INADDR_ANY;
	this->_address.sin_port = htons(port);

	if (bind(this->_socket, (struct sockaddr*)&this->_address, sizeof(this->_address)) < 0)
	{
		Logger::error("Server::Server() at bind");
		exit(EXIT_FAILURE);
	}
}

void Server::Listen()
{
	int client_socket;
	struct sockaddr_in client_address;
	socklen_t client_address_len = sizeof(client_address);
	
	if (listen(this->_socket, 3) < 0)
	{
		Logger::error("Server::Listen() on listen");
		exit(EXIT_FAILURE);
	}
	
	this->onServerListen();
	
	while(true)
	{
		if ((client_socket = accept(this->_socket, (struct sockaddr*)&client_address, &client_address_len)) < 0)
		{
			Logger::error("Server::Listen() on accept");
			exit(EXIT_FAILURE);
		}
		
		switch(this->_type)
		{
			case Server::Type::DNASBypass:
			{
				std::lock_guard<std::mutex> guard(this->_mutex); // server lock

				SSL* ssl = SSL_new(this->_ctx);
				
				std::shared_ptr<Net::Socket> client = std::make_shared<DNASBypass::Client>(client_socket, client_address, ssl);
				
				this->_clients.push_back(client);
				
				this->onClientConnect(client);
				
				std::thread t([client]() {
					static_cast<DNASBypass::Client*>(client.get())->Listen();
				});
				t.detach();
			}
		}
	}
}

void Server::DisconnectAllClients()
{
	for(std::shared_ptr<Net::Socket> client : this->_clients)
	{
		switch(this->_type)
		{
			case Server::Type::DNASBypass:
				dynamic_cast<DNASBypass::Client*>(client.get())->Disconnect();
			break;
		}
	}
}

void Server::Close()
{
	shutdown(this->_socket, SHUT_RDWR);
	
	SSL_CTX_free(this->_ctx);
	
	onServerShutdown();
}

void Server::_InitSSL(const std::map<std::string, std::string> cert_key_files, const std::string& chain_file)
{
	// Create a new SSL context for the server
    this->_ctx = SSL_CTX_new(SSLv23_server_method());
	
	for(auto files : cert_key_files)
	{
		// Load the server certificate and private key files
		if (SSL_CTX_use_certificate_file(this->_ctx, files.first.c_str(), SSL_FILETYPE_PEM) <= 0)
		{
			Logger::error("Failed to load server certificate file \"" + files.first + "\"");
			return;
		}
		else
		{
			Logger::info("Load certificate \"" + files.first + "\"");
		}
		
		if (SSL_CTX_use_PrivateKey_file(this->_ctx, files.second.c_str(), SSL_FILETYPE_PEM) <= 0)
		{
			Logger::error("Failed to load server private key file \"" + files.second + "\"");
			return;
		}
		else
		{
			Logger::info("Load private key \"" + files.second + "\"");
		}
	}
	
	// Load the CA certificate file
	if (SSL_CTX_load_verify_locations(this->_ctx, chain_file.c_str(), nullptr) <= 0)
	{
		Logger::error("Failed to load CA certificate file");
		return;
	}
}

/*
	Events
*/
void Server::onServerListen() const
{	
	Logger::info("Server is now listening on " + this->GetAddress());
}

void Server::onServerShutdown() const
{
	Logger::info("Server shutdown");
}

void Server::onClientConnect(const std::shared_ptr<Net::Socket>& client) const
{
	Logger::info("Client " + client->GetAddress() + " connected", this->_type);
}

void Server::onClientDisconnect(const std::shared_ptr<Net::Socket>& client)
{
	std::lock_guard<std::mutex> guard(this->_mutex); // server lock
	
	auto it = std::find(_clients.begin(), _clients.end(), client);
	
	// When found remove client
	if (it != this->_clients.end())
	{
		Logger::info("Client " + client.get()->GetAddress() + " disconnected", this->_type);

		this->_clients.erase(it);
	}
}

