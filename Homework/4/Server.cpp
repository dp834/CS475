// Just used to hold the port and any other configurable information between the client and server
#include "ASSIGNMENT4.hpp"

using boost::asio::ip::tcp;

// TCP_Connection extends enable shared from this
// This makes TCP_Connection stay alive as long as something
// still has a reference to it
class TCP_Connection
    :public boost::enable_shared_from_this<TCP_Connection>
{
/*TODO: add timeout if nothing is sent from client */
public:
    typedef boost::shared_ptr<TCP_Connection> pointer;

    /* This is how we will initialize new connections using shared ptr */
    static pointer create(boost::asio::io_service& io, std::string rsa_dir)
    {
        return pointer(new TCP_Connection(io, rsa_dir));
    }

    /* getter for the socket */
    tcp::socket& socket()
    {
        return socket_;
    }

    /* what to do when a new connection is made */
    void start()
    {
        /* wait for the client to send it's challenge message*/
        boost::asio::async_read_until(socket_, read_buf, MSG_END,
            /* After getting a response we check the challenge */
            boost::bind(&TCP_Connection::challenge_client, shared_from_this(),
                boost::asio::placeholders::error,
                boost::asio::placeholders::bytes_transferred));
    }

private:
    /* constructor */
    TCP_Connection(boost::asio::io_service& io, std::string rsa_dir)
        : socket_(io),
          to_recv(&read_buf),
          rsa_dir(rsa_dir)
    {

        /* Read server's rsa_keys */
        std::string fname = rsa_dir + "/private.pem";
        FILE *file = fopen(fname.c_str(), "rb");
        if(file){
            rsa_server_private = RSA_new();
            rsa_server_private = PEM_read_RSAPrivateKey(file, &rsa_server_private, NULL,NULL);
        }else{
            std::cerr << "Error opening server private key" << std::endl;
            stop();
        }

        fname = rsa_dir + "/public.pem";
        file = fopen(fname.c_str(), "rb");
        if(file){
            rsa_server_public = RSA_new();
            rsa_server_public = PEM_read_RSA_PUBKEY(file, &rsa_server_public, NULL,NULL);
        }else{
            std::cerr << "Error opening server public key" << std::endl;
            stop();
        }
    }

    /* Once we have a username we can grab their public key */
    int load_client_public_key(){
        /* Public keys are to be stored in the same folder
         * as the server's keys with the format
         * <username>.pem */
        std::string fname = rsa_dir + username + ".pem";
        FILE *file = fopen(fname.c_str(), "rb");
        if(file){
            rsa_client_public = RSA_new();
            rsa_client_public = PEM_read_RSA_PUBKEY(file, &rsa_client_public, NULL,NULL);
        }else{
            std::cerr << "Error opening " << username << "'s public key" << std::endl;
            stop();
            return -1;
        }
        return 0;
    }

    /* Creates an aes key and initializes the encrypt and decrypt context */
    void initialize_aes_parameters(){
        RAND_bytes(aes_key, sizeof(aes_key));
        aes_enc = new AES_KEY();
        aes_dec = new AES_KEY();
        AES_set_encrypt_key(aes_key, sizeof(aes_key)*8, aes_enc);
        AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, aes_dec);
    }

    /* Cleanup things if needed */
    void stop()
    {
        if(username.size()){
            std::cout << "Closing connection with: " << username << std::endl;
        }else{
            std::cout << "Closing connection with unconnected user" << std::endl;
        }
        socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
    }

    /* Check the initial challenge from the client */
    void challenge_client(const boost::system::error_code& error,
        size_t bytes_transferred)
    {
        if(error){
            std::cerr << "Error" << std::endl;
            throw boost::system::system_error(error);
        }

        /* Move the data from the buffer to the string */
        store_recv_msg();

        /* client should have sent their challenge which contains
         * their username encrypted with RSA using the server's public key
         * So we must decrypt using our private RSA key */
        if(RSA_private_decrypt(msg_buf.length(), (unsigned char *)msg_buf.c_str(), tmp_msg_buf, rsa_server_private, RSA_PKCS1_PADDING) < 0){
            ERR_error_string(ERR_get_error(), (char *)tmp_msg_buf);
            std::cerr << "Error decrypting username" << std::endl;
            std::cerr << tmp_msg_buf << std::endl;
            stop();
            return;
        }

        /* Grab the username and put it into a std::string */
        username = (char *) tmp_msg_buf;

        /* Now we know who we are looking for */
        if(load_client_public_key()){
            /* if there is an error loading their key
             * we close */
             return;
        }
        /* Valid user so create an AES key to share */
        initialize_aes_parameters();

        memcpy(&tmp_msg_buf[username.length()], aes_key, sizeof(aes_key));

        int len;
        len = username.length() + sizeof(aes_key);
        /* Make sure our messages are null terminated */
        tmp_msg_buf[len++] = '\0';
        /* used as a buffer during RSA encryption */
        unsigned char tmp[4096];

        /* encrpyt the message using the client's public RSA key */
        if((len = RSA_public_encrypt(len, tmp_msg_buf, tmp, rsa_client_public, RSA_PKCS1_PADDING)) < 0){
            ERR_error_string(ERR_get_error(), (char *)tmp_msg_buf);
            std::cerr << "Error encrypting username and aes keys with client's public key" << std::endl;
            std::cerr << tmp_msg_buf << std::endl;
            stop();
            return;
        }

        /* Encrypt the message using our private key */
        if((len = RSA_private_encrypt(len, tmp, tmp_msg_buf, rsa_server_private, RSA_NO_PADDING)) < 0){
            ERR_error_string(ERR_get_error(), (char *)tmp_msg_buf);
            std::cerr << "Error decrypting username and aes keys with server's private key" << std::endl;
            std::cerr << tmp_msg_buf << std::endl;
            stop();
            return;
        }

        /* Mark the end of the message with the MSG_END string */
        tmp_msg_buf[len++] = '\13';
        tmp_msg_buf[len++] = '\10';

        /* Send the encrypted username and shared key
         * Then spawn a shell and pipe io around */
        boost::asio::async_write(socket_, boost::asio::buffer(tmp_msg_buf, len), boost::asio::transfer_exactly(len),
            boost::bind(&TCP_Connection::open_encrypted_shell, shared_from_this(),
                boost::asio::placeholders::error,
                boost::asio::placeholders::bytes_transferred));
    }

    /* moving  recieved messages from the streambuf to a std::string */
    void store_recv_msg(){
        /* read everything from the buffer until the MSG_END sequence */
        msg_buf.resize(0);
        char c, p;
        to_recv.read(&p, 1);
        while(to_recv){
            to_recv.read(&c, 1);
            if(p == '\13' && c == '\10'){
                break;
            }
            msg_buf += p;
            p = c;
        }
    }

    /* Didn't get around to implementing this part
     * So right now it's just an echo server */
    void open_encrypted_shell(const boost::system::error_code& error,
        size_t bytes_transferred)
    {
        if(error){
            throw boost::system::system_error(error);
            stop();
        }

        /* this will just decrypt whatever is recieved
         * Print it out and re-encrypt it with a new iv
         * and send it back to the client */
        /* The format of these transactions are
         * <iv><encrypted-data> */
        echo_loop();
    }

    /* Makes the first call to read the iv from the client */
    void echo_loop(){
        memset(aes_iv, 0, sizeof(aes_iv));
        boost::asio::async_read(socket_, boost::asio::buffer(aes_iv,sizeof(aes_iv)), boost::asio::transfer_exactly(sizeof(aes_iv)),
            boost::bind(&TCP_Connection::read_aes_iv, shared_from_this(),
                boost::asio::placeholders::error,
                boost::asio::placeholders::bytes_transferred));
    }

    /* Will report errors, if we wanted to do
     * something to the recieved iv it would be here
     * Here we just read the encrypted data */
    void read_aes_iv(const boost::system::error_code& error, size_t bytes_transferred){
        if(error){
            std::cerr << error.message() << std::endl;
            stop();
            return;
        }
        memset(aes_data_enc, 0, sizeof(aes_data_enc));
        boost::asio::async_read(socket_, boost::asio::buffer(aes_data_enc,sizeof(aes_data_enc)),
            boost::asio::transfer_exactly(sizeof(aes_data_enc)),
                boost::bind(&TCP_Connection::read_aes_enc, shared_from_this(),
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
    }

    /* Will report errors
     * Decrypt the encrypted text
     * Print what was recieved from the user
     * then generate new iv for our message to the client */
    void read_aes_enc(const boost::system::error_code& error, size_t bytes_transferred){
        if(error){
            std::cerr << error.message() << std::endl;
            stop();
            return;
        }

        /* decrypt the data */
        AES_cbc_encrypt(aes_data_enc, aes_data_plain, sizeof(aes_data_plain), aes_dec, aes_iv, AES_DECRYPT);
        std::cout<< username << " sent: " << aes_data_plain << std::endl;

        /* New iv for our message to the client */
        RAND_bytes(aes_iv, sizeof(aes_iv));

        boost::asio::async_write(socket_, boost::asio::buffer(aes_iv,sizeof(aes_iv)),
            boost::asio::transfer_exactly(sizeof(aes_iv)),
                boost::bind(&TCP_Connection::write_aes_iv, shared_from_this(),
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
    }

    /* Will report errors
     * Encrypt the data we are going to send
     * and send the data */
    void write_aes_iv(const boost::system::error_code& error, size_t bytes_transferred){
        if(error){
            std::cerr << error.message() << std::endl;
            stop();
            return;
        }

        AES_cbc_encrypt(aes_data_plain, aes_data_enc, sizeof(aes_data_enc), aes_enc, aes_iv, AES_ENCRYPT);

        boost::asio::async_write(socket_, boost::asio::buffer(aes_data_enc, sizeof(aes_data_enc)), boost::asio::transfer_exactly(sizeof(aes_data_enc)),
                boost::bind(&TCP_Connection::write_aes_enc, shared_from_this(),
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
    }

    /* Will report errors 
     * Wait for the client to send a new message to echo back */
    void write_aes_enc(const boost::system::error_code& error, size_t bytes_transferred){
        if(error){
            std::cerr << error.message() << std::endl;
            stop();
            return;
        }

        boost::asio::async_read(socket_, boost::asio::buffer(aes_iv, sizeof(aes_iv)),
            boost::asio::transfer_exactly(sizeof(aes_iv)),
            boost::bind(&TCP_Connection::read_aes_iv, shared_from_this(),
                boost::asio::placeholders::error,
                boost::asio::placeholders::bytes_transferred));
    }



    tcp::socket socket_;
    std::istream to_recv;
    boost::asio::streambuf read_buf;
    std::string msg_buf;
    std::string username;
    std::string rsa_dir;

    /* RSA encryption data */
    RSA *rsa_server_private;
    RSA *rsa_server_public;
    RSA *rsa_client_public;
    unsigned char tmp_msg_buf[256 + sizeof(MSG_END)];

    /* AES encryption data */
    unsigned char aes_key[256/8];
    unsigned char aes_iv[AES_BLOCK_SIZE];
    unsigned char aes_data_plain[1024];
    unsigned char aes_data_enc[1024];
    AES_KEY *aes_enc, *aes_dec;
};

class TCP_Server
{
public:
    /* constructor */
    TCP_Server(boost::asio::io_service& io, std::string& rsa_dir)
        : acceptor_(io, tcp::endpoint(tcp::v4(), PORT_INT)),
          rsa_dir(rsa_dir)
    {
        start_accept();
    }

private:
    /* Wait for new connections
     * when a new connection is made
     * pass socket to the other class to
     * handle communication */
    void start_accept()
    {
        // create a new connection
        TCP_Connection::pointer new_connection =
            TCP_Connection::create(acceptor_.get_io_service(), rsa_dir);

        // setup what to call when someone connects
        acceptor_.async_accept(new_connection->socket(),
            boost::bind(&TCP_Server::handle_accept, this, new_connection,
                boost::asio::placeholders::error));

    }

    /* On connection accept we pass it to the other class */
    void handle_accept(TCP_Connection::pointer new_connection,
        const boost::system::error_code& error)
    {
        if(!error)
        {
            new_connection->start();
        }
        start_accept();
    }

    tcp::acceptor acceptor_;
    std::string rsa_dir;
};

int main(int argc, char *argv[]){
    if(argc != 2){
        std::cout << "Usage: " << argv[0] << " <rsa_keys-dir>" << std::endl;
        std::cout << "This is a simple echo server that uses an encrypted AES connection." << std::endl;
        std::cout << "The key is passed via public key RSA" << std::endl;
        return -1;
    }
    try{
        // required for all io operations through boost
        boost::asio::io_service io;
        std::string rsa_dir(argv[1]);
        TCP_Server server(io, rsa_dir);

        io.run();
    }catch (std::exception& e){
        std::cerr << e.what() << std::endl;
    }

    return 0;
}

