#include <signal.h>
#include <thread>
#include <openssl/ssl.h>

#include <version.h>
#include <logger.h>
#include <server.h>

// Globals
Server* g_dnasbypass_server;

void start_gamestats_server()
{	
	g_dnasbypass_server = new Server(Server::Type::DNASBypass);	
	g_dnasbypass_server->Listen();
}

void Initialize_OpenSSL()
{
	// Initialize the SSL library
    SSL_library_init();
    SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
}

void signal_callback(int signum)
{
	Logger::info("Caught signal " + std::to_string(signum));
	
	// Exit application
	exit(signum);
}

int main(int argc, char const* argv[])
{
	Logger::Initialize();
	Initialize_OpenSSL();
	
	Logger::info("--- PROJECT INFO ---");
	Logger::info("Project name     = " + std::string(PROJECT_GIT_NAME));
	Logger::info("Project toplevel = " + std::string(PROJECT_GIT_TOPLEVEL));
	Logger::info("Branch name      = " + std::string(PROJECT_GIT_BRANCH_NAME));
	Logger::info("Branch hash      = " + std::string(PROJECT_GIT_BRANCH_HASH));
	Logger::info("Version          = " + std::string(PROJECT_VERSION_STRING));
	
	// Register signal callbacks
	signal(SIGINT, signal_callback);
	signal(SIGINT, signal_callback);
	signal(SIGTERM, signal_callback);
	signal(SIGQUIT, signal_callback);
	signal(SIGTSTP, signal_callback);
	
	// Start servers
	std::thread t_dnas_bypass(&start_gamestats_server);
	
	t_dnas_bypass.detach();
	
	// Sleep ZZZZZZzzzzzZZZZZ
	while(true)
	{
		sleep(1);
	}
	
	return EXIT_SUCCESS;
}

