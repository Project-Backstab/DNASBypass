#include <unistd.h>
#include <iostream>
#include <iomanip>
#include <map>

#include <logger.h>
#include <server.h>
#include <globals.h>
#include <util.h>
#include <atomizes.hpp>

#include <dnasbypass/client.h>

using namespace atomizes;

typedef void (DNASBypass::Client::*RequestActionFunc)(const std::vector<unsigned char>&, const atomizes::HTTPMessage&, const UrlRequest::UrlVariables&);

static std::map<std::string, RequestActionFunc> mRequestActions = 
{
	{ "/us-gw/v2.5_i-connect",    &DNASBypass::Client::requestConnect   },
};

DNASBypass::Client::Client(int socket, struct sockaddr_in address, SSL* ssl)
{
	this->_socket = socket;
	this->_address = address;
	this->_ssl = ssl;
}

DNASBypass::Client::~Client()
{
	this->Disconnect();
}

void DNASBypass::Client::Listen()
{
	// Create a new SSL connection object for the client
	SSL_set_fd(this->_ssl, this->_socket);

	// Perform the SSL handshake
	if (SSL_accept(this->_ssl) <= 0)
	{
		Logger::warning("SSL handshake failed", Server::Type::DNASBypass);
	}
	else
	{
		Logger::info("SSL handshake accepted", Server::Type::DNASBypass);
		
		while(true)
		{
			std::vector<unsigned char> buffer(4096, 0);
			HTTPMessageParser http_parser;
			HTTPMessage http_request;
			
			int v = SSL_read(this->_ssl, &(buffer[0]), 4096);
			
			// If error or no data is recieved we end the connection
			if(v <= 0)
			{
				break;
			}
			
			// Resize buffer
			buffer.resize(v);
			
			std::vector<char> buffer2(buffer.begin(), buffer.end());
			
			// Parse buffer to http header
			http_parser.Parse(&http_request, &(buffer2[0]));
			
			// Debug
			//Logger::debug(http_request.ToString());
			
			this->onRequest(buffer, http_request);
		}
	}
	
	this->Disconnect();
}

void DNASBypass::Client::Disconnect()
{
	SSL_shutdown(this->_ssl);
	SSL_free(this->_ssl);
	
	this->Close();
	g_dnasbypass_server->onClientDisconnect(*this);
}

/*
	Events
*/
void DNASBypass::Client::onRequest(const std::vector<unsigned char>& request, const atomizes::HTTPMessage &http_request)
{
	if(http_request.GetMethod() == MessageMethod::POST)
	{
		std::string url_base;
		UrlRequest::UrlVariables url_variables;
		
		this->_LogTransaction("-->", http_request.GetPath());
		
		// Split url into url base and variables
		UrlRequest::GetUrlElements(http_request.GetPath(), url_base, url_variables);
		
		auto it = mRequestActions.find(url_base);
		if (it != mRequestActions.end())
		{
			// Get Function address
			RequestActionFunc func = it->second;
		
			// Execute action function with class object.
			(this->*(func))(request, http_request, url_variables);
		}
		else
		{
			Logger::warning("action \"" + url_base + "\"not implemented!", Server::Type::DNASBypass);
			
			this->Disconnect();
		}
	}
}

void DNASBypass::Client::requestConnect(const std::vector<unsigned char>& request, const atomizes::HTTPMessage& http_request, const UrlRequest::UrlVariables& url_variables)
{
	size_t content_length = this->_GetContentLength(http_request);
	
	if(request.size() < content_length)
	{
		return;
	}
	
	// Debug
	std::stringstream ss;
	for(int i = request.size() - content_length; i < request.size(); i++)
	{
		ss << std::hex << std::setfill('0') << std::setw(2) << (int)(request[i]);
	}
	
	Logger::debug(http_request.ToString());
	Logger::debug("content_length = " + std::to_string(content_length));
	Logger::debug("data = " + ss.str());
	
	
	
	//this->Send(response);
	
	//this->_LogTransaction("<--", str_request);
}

/*
	Private functions
*/
void DNASBypass::Client::_LogTransaction(const std::string& direction, const std::string& response) const
{
	Logger::info(this->GetAddress() + " " + direction + " " + response, Server::Type::DNASBypass, true);
}

size_t DNASBypass::Client::_GetContentLength(const atomizes::HTTPMessage& http_request)
{
	size_t content_length = 0;
	
	// Get first header
	std::string str_content_length = http_request.GetHeader("Content-Length");
	
	// Convert from string to integer
	try
	{
		content_length = std::stoi(str_content_length);
	}
	catch(...) {};
	
	return content_length;
}