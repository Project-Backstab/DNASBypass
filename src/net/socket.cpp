#include <vector>
#include <arpa/inet.h>
#include <unistd.h>

#include <net/socket.h>
#include <logger.h>

Net::Socket::Socket() : _socket(-1)
{
	
}

Net::Socket::~Socket()
{
	this->Close();
}

void Net::Socket::Close() noexcept
{
	std::lock_guard<std::mutex> guard(this->_mutex); // socket lock

	if(this->_socket != -1)
	{
		shutdown(this->_socket, SHUT_RDWR);
		close(this->_socket);
		this->_socket = -1; // Removes reference
	}
}

std::string Net::Socket::GetIP() const
{
	char ip[INET_ADDRSTRLEN];
	
	if(!inet_ntop(AF_INET, &(this->_address.sin_addr), ip, INET_ADDRSTRLEN))
		return "";
	
	return std::string(ip);
}

uint16_t Net::Socket::GetPort() const
{
	return ntohs(this->_address.sin_port);
}

std::string Net::Socket::GetAddress() const
{
	return this->GetIP() + ":" + std::to_string(this->GetPort());
}

std::string Net::Socket::GetSocketType() const
{
	std::lock_guard<std::mutex> guard(this->_mutex);

	int socket_type;
	socklen_t optlen = sizeof(socket_type);

	// Get socket type
	if(getsockopt(this->_socket, SOL_SOCKET, SO_TYPE, &socket_type, &optlen) == -1)
		return "unknown";
	
	switch(socket_type)
	{
		case SOCK_STREAM:
			return "tcp";
		break;
		
		case SOCK_DGRAM:
			return "udp";
		break;
		
		default:
			return "unknown";
		break;
	}
}

std::chrono::system_clock::time_point Net::Socket::GetLastReceivedTime() const
{
	std::lock_guard<std::mutex> guard(this->_mutex); // socket lock

	return this->_received_time;
}

ssize_t Net::Socket::Send(const std::string& msg) const
{
	std::lock_guard<std::mutex> guard(this->_mutex); // socket lock
	
	return send(this->_socket, msg.c_str(), msg.size(), 0);
}

ssize_t Net::Socket::Send(const std::vector<unsigned char>& msg) const
{
	std::lock_guard<std::mutex> guard(this->_mutex); // socket lock
	
	return send(this->_socket, msg.data(), msg.size(), 0);
}

void Net::Socket::UpdateLastReceivedTime()
{
	std::lock_guard<std::mutex> guard(this->_mutex); // socket lock

	this->_received_time = std::chrono::system_clock::now();
}

