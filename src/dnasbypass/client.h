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
			void Send(const std::string& msg) const;
			void Send(const std::vector<unsigned char>& msg) const;
			
			/*
				Events
			*/
			void onRequest(const std::vector<unsigned char>& request, const atomizes::HTTPMessage &http_request);
			
			/*
				Requests
			*/
			void requestConnect(const std::vector<unsigned char>& request, const atomizes::HTTPMessage& http_request,
					const UrlRequest::UrlVariables& url_variables);
			void requestOther(const std::vector<unsigned char>& request, const atomizes::HTTPMessage& http_request,
					const UrlRequest::UrlVariables& url_variables);
			
		private:
			void _LogTransaction(const std::string& direction, const std::string& response) const;
			size_t _GetContentLength(const atomizes::HTTPMessage& http_request);
		public:
			static void Test();
			static void GetFileName(const std::vector<unsigned char>& packet1, std::string& game_id,
					std::string& query_type, std::string& file_name);
			static void GetFileNameOther(const std::vector<unsigned char>& packet1, std::string& game_id,
					std::string& query_type, std::string& file_name);
			static void GetChecksums(const std::vector<unsigned char>& packet1, std::vector<unsigned char>& chksum1,
					std::vector<unsigned char>& chksum2);
			static void GetKeysAndSeed(const std::vector<unsigned char> chksum1, const std::vector<unsigned char> chksum2,
					std::vector<unsigned char>& des_key1, std::vector<unsigned char>& des_key2,
					std::vector<unsigned char>& des_key3, std::vector<unsigned char>& xor_seed);
			static void Sign(const std::vector<unsigned char>& packet1, std::vector<unsigned char>& packet4);
	};
}

#endif // DNASBYPASS_CLIENT_H
