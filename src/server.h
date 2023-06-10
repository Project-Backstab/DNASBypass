#ifndef SERVER_H
#define SERVER_H

#include <vector>
#include <openssl/ssl.h>

#include <net/socket.h>

class Server : public Net::Socket
{
	public:
		enum Type
		{
			DNASBypass,
			None
		};
	
	private:
		std::vector<Net::Socket*> _clients;
		Server::Type              _type;
		SSL_CTX*                  _ctx;
	
	public:
		Server(Server::Type type);
		void Listen();
		void DisconnectAllClients();
		void Close();
	
	private:
		void _InitSSL(const std::string& cert_file, const std::string& key_file, const std::string& chain_file);
		
	public:
		// Events
		void onServerListen() const;
		void onServerShutdown() const;
		void onClientConnect(const Net::Socket& client) const;
		void onClientDisconnect(const Net::Socket& client);
};

#endif // SERVER_H
