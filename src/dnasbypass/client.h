#ifndef DNASBYPASS_CLIENT_H
#define DNASBYPASS_CLIENT_H

#include <net/socket.h>
#include <urlrequest.h>

// Forward declair
namespace atomizes
{
	class HTTPMessage;
};

namespace DNASBypass
{
	class Client : public Net::Socket
	{
		private:
			SSL* _ssl;
		
		public:
			Client(int socket, struct sockaddr_in address, SSL* ssl);
			~Client();
			
			void Listen();
			void Disconnect();
			
			/*
				Events
			*/
			void onRequest(const atomizes::HTTPMessage &http_request);
			
			/*
				Requests
			*/
			void requestConnect(const atomizes::HTTPMessage& http_request, const UrlRequest::UrlVariables& url_variables);
			
		private:
			void _LogTransaction(const std::string& direction, const std::string& response) const;
	};
}

#endif // DNASBYPASS_CLIENT_H
