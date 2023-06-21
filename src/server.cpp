#include <algorithm>
#include <unistd.h>
#include <thread>

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
		
		SSL* ssl = SSL_new(this->_ctx);
		
		Net::Socket* client = new DNASBypass::Client(client_socket, client_address, ssl);
		
		this->onClientConnect(*client);
		
		std::thread t(&DNASBypass::Client::Listen, (DNASBypass::Client*)client);
		t.detach();
		
		this->_clients.push_back(client);
	}
}

void Server::DisconnectAllClients()
{
	for(Net::Socket* client : this->_clients)
	{
		// ((GPSP::Client*)client)->Disconnect();
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

void Server::onClientConnect(const Net::Socket& client) const
{
	Logger::info("Client " + client.GetAddress() + " connected");
}

void Server::onClientDisconnect(const Net::Socket& client)
{
	Logger::info("Client " + client.GetAddress() + " disconnected");
	
	auto it = std::find(this->_clients.begin(), this->_clients.end(), const_cast<Net::Socket*>(&client));
	if (it != this->_clients.end())
	{
		this->_clients.erase(it);
		
		delete &client;
	}
}

