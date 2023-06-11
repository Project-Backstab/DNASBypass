#include <unistd.h>
#include <iostream>
#include <iomanip>
#include <map>
#include <openssl/sha.h>
#include <openssl/des.h>

#include <logger.h>
#include <server.h>
#include <globals.h>
#include <util.h>
#include <atomizes.hpp>

#include <dnasbypass/client.h>

using namespace atomizes;

std::vector<unsigned char> example_A_packet1 =
{
	// Query type
	0x01, 0x18, 0x00, 0x00,
	
	// ? Unknown ?
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x0c, 0x00, 0x02, 0x00, 0x05,
	
	// Game ID
	0xca, 0x08, 0x10, 0x76, 0x7e, 0x46, 0x1a, 0x49,
	
	// Random data
	0x10, 0xa0, 0x5d, 0xdd, 0x78, 0xcc, 0x6c, 0x07, 0x08, 0xb9, 0xbf, 0xd9, 0x6e, 0x52, 0x5f, 0x61,
	0xc0, 0xd2, 0x10, 0x3b, 0x35, 0x73, 0xea, 0xb8, 0x30, 0xaa, 0x2e, 0x55, 0x96, 0x99, 0x62, 0xc0,
	0x8e, 0x3f, 0x6d, 0x3f, 0xfb, 0xb7, 0x37, 0xd6, 0xf9, 0x1e, 0x29, 0xa5, 0x82, 0xe1, 0xb3, 0x86,
	0x4f, 0x91, 0x22, 0xb5, 0x88, 0xe5, 0x8a, 0x67, 0x16, 0xd1, 0x52, 0xcf, 0x5e, 0xea, 0xa9, 0x53,
	0xc4, 0x52, 0x7b, 0x1f, 0x29, 0x0b, 0x12, 0x6f, 0x2d, 0xa7, 0xe5, 0x18, 0x56, 0xea, 0x68, 0x14,
	0x93, 0x37, 0x9c, 0x76, 0x40, 0x74, 0x05, 0x5c, 0x77, 0xd6, 0x9a, 0xa2, 0xd4, 0x8e, 0x54, 0x54,
	0xc2, 0xea, 0x43, 0x5d, 0xf8, 0xa9, 0xd6, 0xf0, 0x72, 0x5e, 0xeb, 0xa6, 0xfd, 0xd0, 0xbc, 0x38,
	0xf1, 0x6d, 0xe6, 0x56, 0x39, 0x29, 0x1d, 0xa3, 0x0c, 0xd8, 0x41, 0x48, 0x9c, 0xda, 0x49, 0xfb,
	0x50, 0xdc, 0x59, 0x95, 0xfd, 0x32, 0x48, 0x7e, 0x16, 0x22, 0xb5, 0x40, 0xa9, 0xab, 0x75, 0x23,
	0x68, 0xa9, 0xe6, 0x46, 0xcb, 0x82, 0x01, 0x48, 0x0d, 0x96, 0x58, 0xa9, 0x23, 0x50, 0xb3, 0xad,
	0xf3, 0x45, 0x43, 0xca, 0x32, 0x41, 0x6a, 0xc1, 0x2c, 0x5c, 0xae, 0x15, 0x46, 0x4c, 0xc8, 0xb3,
	0x8f, 0xb8, 0xe7, 0xee, 0x8c, 0x8d, 0x88, 0xd3, 0xce, 0xbe, 0x25, 0xfb, 0xef, 0x77, 0x2c, 0x1f,
	0xbe, 0xd9, 0xda, 0x5a, 0x5a, 0x1d, 0x54, 0x22, 0xda, 0xfd, 0xb2, 0xbd, 0x2b, 0x07, 0x85, 0xec,
	0xa7, 0x6f, 0x37, 0x3c, 0x5f, 0x3b, 0x5d, 0x51, 0x3f, 0xf5, 0x6c, 0xa4, 0x6d, 0xda, 0x63, 0x91,
	0x8d, 0x38, 0x49, 0x68, 0x76, 0xba, 0xbf, 0xa7, 0x7e, 0x55, 0x4e, 0x74, 0x5a, 0x13, 0xc0, 0xbb,
	0xe6, 0x3b, 0x63, 0xae, 0x24, 0x6f, 0x54, 0x17, 0xb9, 0x66, 0xf1, 0xcd, 0xc9, 0x12, 0x34, 0x95
};

// File name: ca0810767e461a49_01180000
std::vector<unsigned char> example_A_packet2 =
{
	0x01, 0x18, 0x00, 0x05, 0x01, 0x0E, 0x5C, 0x55, 0x17, 0x38, 0x16, 0x12, 0x09, 0x07, 0xE0, 0x00,
	0x00, 0x33, 0xA8, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x8C, 0xB3, 0x8E, 0x6D, 0x07,
	0x6D, 0x27, 0x5D, 0xDF, 0x00, 0x00, 0x01, 0x20, 0xD0, 0xDC, 0x99, 0x19, 0xF1, 0x1E, 0x42, 0x85,
	0x9A, 0xE1, 0xAA, 0x19, 0x3C, 0x08, 0x35, 0x84, 0x7D, 0xC7, 0x57, 0x3A, 0xD3, 0xE2, 0x7A, 0x54,
	0x1D, 0x75, 0x0B, 0xF6, 0xFC, 0x52, 0x12, 0x32, 0x3A, 0x6C, 0xDE, 0xA9, 0x7E, 0x33, 0x8A, 0x6D,
	0x04, 0x93, 0xE3, 0x30, 0xDB, 0x59, 0x7C, 0x91, 0x47, 0x10, 0xEC, 0x17, 0x56, 0xBD, 0xA5, 0x52,
	0x87, 0x79, 0x3D, 0x99, 0x0B, 0x79, 0x03, 0x46, 0xAF, 0x0F, 0x04, 0x5E, 0x47, 0x1F, 0x4F, 0x9B,
	0xDD, 0xD8, 0x33, 0x72, 0x29, 0x4B, 0x42, 0xCE, 0x06, 0x5C, 0x6E, 0x52, 0x21, 0xDE, 0xC7, 0xA0,
	0x54, 0x56, 0xAC, 0xED, 0xDF, 0x7E, 0x4A, 0xDE, 0xB3, 0x4D, 0x0B, 0xAB, 0x5C, 0x9E, 0x55, 0xE8,
	0xFC, 0x17, 0x36, 0xD6, 0xD2, 0x61, 0xBA, 0xA5, 0xB1, 0xD5, 0xD2, 0x4A, 0x09, 0x45, 0x06, 0x31,
	0x81, 0x81, 0xDB, 0xDA, 0x57, 0xE6, 0xCC, 0xBE, 0x8E, 0x1A, 0x8E, 0x01, 0x3C, 0xDE, 0x2E, 0x53,
	0x9D, 0x08, 0xFB, 0x78, 0x14, 0x27, 0xB4, 0xE9, 0xFB, 0xD9, 0xF1, 0x10, 0x6B, 0x75, 0xE9, 0xC0,
	0xBF, 0x6D, 0xF9, 0xD7, 0x7F, 0x44, 0x4D, 0x55, 0xE0, 0x80, 0x76, 0x4E, 0xF5, 0xC1, 0x0C, 0x97,
	0x36, 0xD6, 0xE3, 0xE9, 0x4C, 0x23, 0x02, 0x2F, 0x4F, 0x09, 0xE0, 0xB7, 0xC6, 0x14, 0xC2, 0x40,
	0x9A, 0x79, 0xA3, 0x5C, 0xD7, 0xC4, 0xB7, 0xB7, 0x84, 0x7A, 0xF5, 0xF3, 0xE3, 0x04, 0x14, 0xCC,
	0x81, 0x3F, 0xF6, 0x74, 0x31, 0xC1, 0xC2, 0xCA, 0xD3, 0xA7, 0xCF, 0x34, 0x34, 0xB0, 0x65, 0x2F,
	0x5B, 0xAD, 0xB9, 0x45, 0x55, 0xD2, 0x33, 0xDA, 0x4C, 0x29, 0xCD, 0x2F, 0x2E, 0xE2, 0xFC, 0xAF,
	0x21, 0xF2, 0x23, 0x53, 0xB4, 0xE6, 0x1D, 0x88, 0x8D, 0xEC, 0xBD, 0xC2, 0x9D, 0x22, 0xF1, 0xF8,
	0xD0, 0xAB, 0x3E, 0x26, 0x7D, 0x71, 0x00, 0xC9, 0x9B, 0xCE, 0xF9, 0xC9, 0xB0, 0xF5, 0x78, 0xD2,
	0xE8, 0x9C, 0x25, 0x9C, 0x82, 0x42, 0x25, 0x10, 0x2E, 0xE2, 0xD2, 0xCB, 0x04, 0xC3, 0xC4, 0xD5,
	0x6E, 0x02, 0xFC, 0xEB, 0x74, 0xFC, 0xB5, 0x10
};

// File name: 8cb38e6d076d275d_01188001
std::vector<unsigned char> example_A_other_packet2 =
{
	0x01, 0x18, 0x80, 0x06, 0x01, 0x0E, 0x5C, 0x55, 0x17, 0x38, 0x16, 0x12, 0x09, 0x07, 0xE0, 0x00,
	0x00, 0x33, 0xA8, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x8C, 0xB3, 0x8E, 0x6D, 0x07,
	0x6D, 0x27, 0x5D, 0xDF, 0x00, 0x00, 0x00, 0x82, 0x02, 0x01, 0xA6, 0x70, 0x7B, 0x55, 0xB4, 0x28,
	0x97, 0xA3, 0x7E, 0x3A, 0xFA, 0xD3, 0xE4, 0x54, 0xAC, 0xB7, 0xEB, 0x68, 0xC7, 0xF5, 0xB4, 0x19,
	0xBE, 0x1C, 0x9C, 0x4D, 0x62, 0xCC, 0xA9, 0xBF, 0xA1, 0x66, 0xED, 0xF9, 0x4E, 0x6A, 0x44, 0x99,
	0xC0, 0xFB, 0x9C, 0x14, 0xD7, 0x67, 0x45, 0x85, 0x0D, 0x4F, 0xE9, 0x2D, 0x35, 0x10, 0xE5, 0xF9,
	0xEC, 0x2C, 0x82, 0x8E, 0xF1, 0xAE, 0x37, 0x55, 0xC3, 0xE1, 0xE4, 0x16, 0xB4, 0x9C, 0xEE, 0x7C,
	0x5A, 0x53, 0x24, 0xE4, 0x53, 0xDB, 0x48, 0x88, 0xC7, 0xDC, 0x77, 0xD8, 0x90, 0xAD, 0x82, 0x31,
	0xCA, 0x28, 0x64, 0x10, 0xE7, 0x3E, 0x4C, 0xE0, 0x85, 0x8C, 0xA7, 0xBB, 0xC2, 0xB5, 0xD7, 0xC7,
	0x6C, 0x48, 0x35, 0x15, 0xB2, 0x3B, 0x32, 0x34, 0x77, 0x0D, 0x2C, 0xF0, 0x4F, 0xC9, 0x2B, 0xBA,
	0x49, 0x59, 0x02, 0xAC, 0xEF, 0x72, 0x27, 0x02, 0xFC, 0xAF
};

typedef void (DNASBypass::Client::*RequestActionFunc)(const std::vector<unsigned char>&, const atomizes::HTTPMessage&, const UrlRequest::UrlVariables&);

static std::map<std::string, RequestActionFunc> mRequestActions = 
{
	{ "/us-gw/v2.5_i-connect",    &DNASBypass::Client::requestConnect },
	{ "/us-gw/v2.5_others",       &DNASBypass::Client::requestOther   },
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

void DNASBypass::Client::Send(const std::string& msg) const
{
	std::lock_guard<std::mutex> guard(this->_mutex); // socket lock (read/write)
	
	Logger::debug("Send!");
	
	SSL_write(this->_ssl, msg.c_str(), msg.size());
}

void DNASBypass::Client::Send(const std::vector<unsigned char>& msg) const
{
	std::lock_guard<std::mutex> guard(this->_mutex); // socket lock (read/write)
	
	Logger::debug("Send!");
	
	SSL_write(this->_ssl, &(msg[0]), msg.size());
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
			Logger::warning("action \"" + url_base + "\" not implemented!", Server::Type::DNASBypass);
		}
	}
	else
	{
		Logger::warning("And none POST request recieved!", Server::Type::DNASBypass);
	}
}

void DNASBypass::Client::requestConnect(const std::vector<unsigned char>& request, const atomizes::HTTPMessage& http_request,
		const UrlRequest::UrlVariables& url_variables)
{
	std::vector<unsigned char> packet1;
	std::vector<unsigned char> packet4;
	std::vector<unsigned char> v_response;
	std::string response;
	
	// Get content length, because this http header exist twice we need to take the first
	size_t content_length = this->_GetContentLength(http_request);
	
	if(request.size() < content_length)
	{
		return; // WTF?!
	}
	
	// Get requested file data
	packet1.assign(request.end() - content_length, request.end());
	
	// Sign data
	Sign(packet1, packet4);
	
	response += "HTTP/1.0 200 OK\r\n";
	response += "Content-Type: image/gif\r\n";
	response += "Content-Length: " + std::to_string(packet4.size()) + "\r\n\r\n";
	
	v_response.reserve(response.size() + packet4.size());
	
	std::copy(response.begin(), response.end(), std::back_inserter(v_response));
	std::copy(packet4.begin(), packet4.end(), std::back_inserter(v_response));
	
	this->Send(v_response);
	this->_LogTransaction("<--", response);
	
	// Debug
	std::stringstream ss;
	
	Logger::debug(http_request.ToString());
	Logger::debug("content_length = " + std::to_string(content_length));
	
	for(int i = 0; i < packet1.size(); i++)
	{
		ss << std::hex << std::setfill('0') << std::setw(2) << (int)(packet1[i]);
	}
	Logger::debug("packet1 = " + ss.str());
	
	ss.str("");
	for(int i = 0; i < packet4.size(); i++)
	{
		ss << std::hex << std::setfill('0') << std::setw(2) << (int)(packet4[i]);
	}
	Logger::debug("packet4 = " + ss.str());
	
	Logger::debug("response = " + response);
}

void DNASBypass::Client::requestOther(const std::vector<unsigned char>& request, const atomizes::HTTPMessage& http_request, const UrlRequest::UrlVariables& url_variables)
{
	std::vector<unsigned char> packet1;
	std::string game_id;
	std::string query_type;
	std::string file_name;
	std::vector<unsigned char> packet2 = example_A_other_packet2;
	std::vector<unsigned char> v_response;
	std::string response;
	
	// Get content length, because this http header exist twice we need to take the first
	size_t content_length = this->_GetContentLength(http_request);
	
	if(request.size() < content_length)
	{
		return; // WTF?!
	}
	
	// Get requested file data
	packet1.assign(request.end() - content_length, request.end());
	
	// Extract information
	GetFileNameOther(packet1, game_id, query_type, file_name);
	
	response += "HTTP/1.0 200 OK\r\n";
	response += "Content-Type: image/gif\r\n";
	response += "Content-Length: " + std::to_string(packet2.size()) + "\r\n\r\n";
	
	v_response.reserve(response.size() + packet2.size());
	
	std::copy(response.begin(), response.end(), std::back_inserter(v_response));
	std::copy(packet2.begin(), packet2.end(), std::back_inserter(v_response));
	
	this->Send(v_response);
	this->_LogTransaction("<--", response);
	
	// Debug
	std::stringstream ss;
	
	Logger::debug(http_request.ToString());
	Logger::debug("content_length = " + std::to_string(content_length));
	
	Logger::debug("game_id = " + game_id);
	Logger::debug("query_type = " + query_type);
	Logger::debug("file_name = " + file_name);
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

#define DES_KEY_SIZE  8
#define XOR_KEY_SIZE  8

std::vector<unsigned char> encrypt3(const std::vector<unsigned char>& data, int offset, int length,
		const std::vector<unsigned char>& des_key1, const std::vector<unsigned char>& des_key2,
		const std::vector<unsigned char>& des_key3, const std::vector<unsigned char>& xor_seed)
{
    std::vector<unsigned char> encryptedData = data;
    std::vector<unsigned char> key = xor_seed;

    for (int i = 0; i < length; i += 8)
	{
        std::vector<unsigned char> dat(encryptedData.begin() + offset + i, encryptedData.begin() + offset + i + 8);
        
		for (int t = 0; t < 8; t++)
		{
            dat[t] = dat[t] ^ key[t];
        }

        DES_key_schedule ks1, ks2, ks3;
        DES_set_key((const_DES_cblock*)des_key1.data(), &ks1);
        DES_set_key((const_DES_cblock*)des_key2.data(), &ks2);
        DES_set_key((const_DES_cblock*)des_key3.data(), &ks3);

        DES_ecb_encrypt((const_DES_cblock*)dat.data(), (DES_cblock*)dat.data(), &ks1, DES_ENCRYPT);
        DES_ecb_encrypt((const_DES_cblock*)dat.data(), (DES_cblock*)dat.data(), &ks2, DES_DECRYPT);
        DES_ecb_encrypt((const_DES_cblock*)dat.data(), (DES_cblock*)dat.data(), &ks3, DES_ENCRYPT);

        for (int t = 0; t < 8; t++)
		{
            encryptedData[offset + i + t] = dat[t];
        }
		
        key = dat;
    }

    return encryptedData;
}

/*
	See "data/example/script.php"
*/
void DNASBypass::Client::Test()
{
	std::vector<unsigned char> packet1 = example_A_packet1;
	
	std::string   game_id;
	std::string   query_type;
	std::string   file_name;
	std::vector<unsigned char> chksum1(SHA_DIGEST_LENGTH, 0);
	std::vector<unsigned char> chksum2(SHA_DIGEST_LENGTH, 0);
	std::vector<unsigned char> des_key1(DES_KEY_SIZE, 0);
	std::vector<unsigned char> des_key2(DES_KEY_SIZE, 0);
	std::vector<unsigned char> des_key3(DES_KEY_SIZE, 0);
	std::vector<unsigned char> xor_seed(XOR_KEY_SIZE, 0);
	std::vector<unsigned char> des_key4  = { 0xeb, 0x71, 0x14, 0x16, 0xcb, 0x0a, 0xb0, 0x16 };
	std::vector<unsigned char> des_key5  = { 0xae, 0x19, 0x01, 0x74, 0xb5, 0xce, 0x63, 0x39 };
	std::vector<unsigned char> des_key6  = { 0x7b, 0x01, 0xb9, 0x18, 0x80, 0x14, 0x5e, 0x34 };
	std::vector<unsigned char> xor_seed2 = { 0xc5, 0x10, 0xa6, 0x40, 0x0a, 0x9b, 0x02, 0x2f };
	std::vector<unsigned char> packet2 = example_A_packet2;
	std::vector<unsigned char> packet3;
	std::vector<unsigned char> packet4;
	
	GetFileName(packet1, game_id, query_type, file_name);
	GetChecksums(packet1, chksum1, chksum2);
	GetKeysAndSeed(chksum1, chksum2, des_key1, des_key2, des_key3, xor_seed);
	
	packet3 = encrypt3(packet2, 0xc8, 0x20, des_key1, des_key2, des_key3, xor_seed);
	packet4 = encrypt3(packet3, 0x28, 0x120, des_key4, des_key5, des_key6, xor_seed2);
		
	// Debug
	std::stringstream ss, ss2, ss3;
	
	ss.str("");
	for(int i = 0; i < packet1.size(); i++)
	{
		ss  << std::hex << std::setfill('0') << std::setw(2) << (int)(packet1[i]);
	}
	Logger::debug("packet1    = " + ss.str());
	
	Logger::debug("game_id    = " + game_id);
	Logger::debug("query_type = " + query_type);
	Logger::debug("file_name  = " + file_name);
	
	ss.str("");
	ss2.str("");
	for(int i = 0; i < SHA_DIGEST_LENGTH; i++)
	{
		ss  << std::hex << std::setfill('0') << std::setw(2) << (int)(chksum1[i]);
		ss2 << std::hex << std::setfill('0') << std::setw(2) << (int)(chksum2[i]);
	}
	Logger::debug("chksum1    = " + ss.str());
	Logger::debug("chksum2    = " + ss2.str());
	
	ss.str("");
	ss2.str("");
	ss3.str("");
	for(int i = 0; i < DES_KEY_SIZE; i++)
	{
		ss  << std::hex << std::setfill('0') << std::setw(2) << (int)(des_key1[i]);
		ss2 << std::hex << std::setfill('0') << std::setw(2) << (int)(des_key2[i]);
		ss3 << std::hex << std::setfill('0') << std::setw(2) << (int)(des_key3[i]);
	}
	Logger::debug("des_key1   = " + ss.str());
	Logger::debug("des_key2   = " + ss2.str());
	Logger::debug("des_key3   = " + ss3.str());
	
	ss.str("");
	for(int i = 0; i < XOR_KEY_SIZE; i++)
	{
		ss  << std::hex << std::setfill('0') << std::setw(2) << (int)(xor_seed[i]);
	}
	Logger::debug("xor_seed   = " + ss.str());
	
	ss.str("");
	ss2.str("");
	ss3.str("");
	for(int i = 0; i < DES_KEY_SIZE; i++)
	{
		ss  << std::hex << std::setfill('0') << std::setw(2) << (int)(des_key4[i]);
		ss2 << std::hex << std::setfill('0') << std::setw(2) << (int)(des_key5[i]);
		ss3 << std::hex << std::setfill('0') << std::setw(2) << (int)(des_key6[i]);
	}
	Logger::debug("des_key4   = " + ss.str());
	Logger::debug("des_key5   = " + ss2.str());
	Logger::debug("des_key6   = " + ss3.str());
	
	ss.str("");
	for(int i = 0; i < XOR_KEY_SIZE; i++)
	{
		ss  << std::hex << std::setfill('0') << std::setw(2) << (int)(xor_seed2[i]);
	}
	Logger::debug("xor_seed2  = " + ss.str());
	
	ss.str("");
	for(int i = 0; i < packet2.size(); i++)
	{
		ss  << std::hex << std::setfill('0') << std::setw(2) << (int)(packet2[i]);
	}
	Logger::debug("packet2  = " + ss.str());
	
	ss.str("");
	for(int i = 0; i < packet3.size(); i++)
	{
		ss  << std::hex << std::setfill('0') << std::setw(2) << (int)(packet3[i]);
	}
	Logger::debug("packet3  = " + ss.str());
	
	ss.str("");
	for(int i = 0; i < packet4.size(); i++)
	{
		ss  << std::hex << std::setfill('0') << std::setw(2) << (int)(packet4[i]);
	}
	Logger::debug("packet4  = " + ss.str());
}

/*
	Generate checksums
*/
void DNASBypass::Client::GetChecksums(const std::vector<unsigned char>& packet1, std::vector<unsigned char>& chksum1,
	std::vector<unsigned char>& chksum2)
{
	SHA1(&(packet1[0x34]), 0x100, &(chksum1[0]));
	SHA1(&(packet1[0x48]), 0xec, &(chksum2[0]));
}

void DNASBypass::Client::GetFileName(const std::vector<unsigned char>& packet1, std::string& game_id, std::string& query_type,
		std::string& file_name)
{
	std::stringstream ss, ss2;
	
	for(int i = 0; i < 8; i++)
	{
		ss  << std::hex << std::setfill('0') << std::setw(2) << (int)(packet1[i + 0x2c]);
		
		if(i < 4)
		{
			ss2 << std::hex << std::setfill('0') << std::setw(2) << (int)(packet1[i]);
		}
	}
	game_id = ss.str();
	query_type = ss2.str();
	
	file_name = game_id + "_" + query_type;
}

void DNASBypass::Client::GetFileNameOther(const std::vector<unsigned char>& packet1, std::string& game_id, std::string& query_type,
		std::string& file_name)
{
	std::stringstream ss, ss2;
	
	for(int i = 0; i < 8; i++)
	{
		ss  << std::hex << std::setfill('0') << std::setw(2) << (int)(packet1[i + 0x1b]);
		
		if(i < 4)
		{
			ss2 << std::hex << std::setfill('0') << std::setw(2) << (int)(packet1[i]);
		}
	}
	game_id = ss.str();
	query_type = ss2.str();
	
	file_name = game_id + "_" + query_type;
}

void DNASBypass::Client::GetKeysAndSeed(const std::vector<unsigned char> chksum1, const std::vector<unsigned char> chksum2,
		std::vector<unsigned char>& des_key1, std::vector<unsigned char>& des_key2, std::vector<unsigned char>& des_key3,
		std::vector<unsigned char>& xor_seed)
{
	// Get des keys and xor seed from checksums
	for(int i = 0; i < DES_KEY_SIZE; i++)
	{
		des_key1[i] = chksum2[i];
		des_key2[i] = chksum2[8 + i];
		
		if(i < 4)
		{
			des_key3[i] = chksum2[16 + i];
			des_key3[i + 4] = chksum1[i];
		}
		
		xor_seed[i] = chksum1[i + 4];
	}
}

void DNASBypass::Client::Sign(const std::vector<unsigned char>& packet1, std::vector<unsigned char>& packet4)
{
	std::string   game_id;
	std::string   query_type;
	std::string   file_name;
	std::vector<unsigned char> chksum1(SHA_DIGEST_LENGTH, 0);
	std::vector<unsigned char> chksum2(SHA_DIGEST_LENGTH, 0);
	std::vector<unsigned char> des_key1(DES_KEY_SIZE, 0);
	std::vector<unsigned char> des_key2(DES_KEY_SIZE, 0);
	std::vector<unsigned char> des_key3(DES_KEY_SIZE, 0);
	std::vector<unsigned char> xor_seed(XOR_KEY_SIZE, 0);
	std::vector<unsigned char> des_key4  = { 0xeb, 0x71, 0x14, 0x16, 0xcb, 0x0a, 0xb0, 0x16 };
	std::vector<unsigned char> des_key5  = { 0xae, 0x19, 0x01, 0x74, 0xb5, 0xce, 0x63, 0x39 };
	std::vector<unsigned char> des_key6  = { 0x7b, 0x01, 0xb9, 0x18, 0x80, 0x14, 0x5e, 0x34 };
	std::vector<unsigned char> xor_seed2 = { 0xc5, 0x10, 0xa6, 0x40, 0x0a, 0x9b, 0x02, 0x2f };
	std::vector<unsigned char> packet2 = example_A_packet2;
	std::vector<unsigned char> packet3;
	
	GetFileName(packet1, game_id, query_type, file_name);
	GetChecksums(packet1, chksum1, chksum2);
	GetKeysAndSeed(chksum1, chksum2, des_key1, des_key2, des_key3, xor_seed);
	
	packet3 = encrypt3(packet2, 0xc8, 0x20, des_key1, des_key2, des_key3, xor_seed);
	packet4 = encrypt3(packet3, 0x28, 0x120, des_key4, des_key5, des_key6, xor_seed2);
}

