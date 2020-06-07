// Symmetric
#include <openssl/aes.h>
// Public key
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

// Library for wrapping c functions in a c++ manner
// Using it as an opportunity to learn how to as it's common in the industry for c++
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/shared_ptr.hpp>

#include <string>
#include <iostream>

#include <fstream>

// some places need it as a string while others want an int
#define PORT_INT 9453
#define PORT_STR "9453"

#define MSG_END "\13\10"
