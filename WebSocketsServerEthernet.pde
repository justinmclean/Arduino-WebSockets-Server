#include <Ethernet.h>
#include <SPI.h>

#include <sha1.h>
#include <Base64.h>

byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
byte ip[] = { 10,0,0,50 };
String ipaddress = "10.0.0.50";

const char hex[] ="0123456789abcdef";

boolean websocket = false;
boolean handshakeDone = false;
String key;

Server server(80);

void setup()
{
  Ethernet.begin(mac, ip);
  server.begin();
  //Serial.begin(9600);
}

// Read a line at a time
String readLine(Client client)
{
  String data;

  while (client.available()) 
  {
    char c = client.read();

    data.concat(c);
    if (c == '\n') {
      return data;
    }  
  }
}

// Return true is line is "blank"
boolean blankLine(String line) {
  return (line.length() == 2 && line[0] == '\r' && line[1] == '\n');
}

// Send a standard http response header
void httpOK(Client client) {
  client.println("HTTP/1.1 200 OK");
  client.println("Content-Type: text/html");
  client.println();
}

// Send a header to switch to the web sockets protocol
void webSocketOK(Client client, String key) {
  client.println("HTTP/1.1 101 Switching Protocols");
  client.println("Upgrade: websocket");
  client.println("Connection: Upgrade");
  client.print("Sec-WebSocket-Accept: ");
  client.println(key);
  client.println();
}

// Convert a SHA1 hash to a string
char* hashToString(uint8_t* hash) {
  char hashStr[40];

  for (int i=0; i < 20; i++) {
    hashStr[2*i] = hex[hash[i] >> 4];
    hashStr[2*i+1] = hex[hash[i] & 0xf];     
  }
  hashStr[40] = '\0';

  return hashStr;
}

// read a HTTP header a line at a time and decode
void readHeader(Client client) {
  String line = readLine(client); 
  int colon = line.indexOf(":");

  if (colon) {
    String name = line.substring(0, colon).trim();
    String value = line.substring(colon + 1).trim();
    
    if (name == "Upgrade" && value == "websocket") {
      websocket = true;
    }
    if (name == "Sec-WebSocket-Key") {
      key = value;
    }
  }

  if (blankLine(line)) { 
    if (websocket) { 
      key = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
      Sha1.init();
      Sha1.print(key);
      char* hash = (char*)Sha1.result();
      char encode[29];
      base64_encode(encode, hash, 20);
      webSocketOK(client, encode);
      handshakeDone = true;
    }
    else {
      httpOK(client);
    }
  }
}

// read and decode a web socket message
String readMessage(Client client)
{
  String data;
  unsigned char opcode;
  unsigned char length;
  boolean useMask;
  unsigned char mask[4];

  opcode = client.read();
  //TODO check opcode
  length = client.read();
  useMask = ((length & 0x80) == 0x80);
  length = length & 0x7F;
  if (useMask) {
    mask[0] = client.read();
    mask[1] = client.read();
    mask[2] = client.read();
    mask[3] = client.read();
  }

  int noRead = 0;  
  while (noRead < length) 
  {
    unsigned char masked = client.read();

    if (useMask) {
      unsigned char unmasked = masked ^ mask[noRead % 4];
      data.concat(unmasked);
    }
    else {
      data.concat(masked);
    }

    noRead++;
  }

  return data;
}

// encode and send a web socket message
void sendMessage(Client client, String message) {
  unsigned char mask[4];
  int length = message.length();
  
  mask[0] = random(256);
  mask[1] = random(256);
  mask[2] = random(256);
  mask[3] = random(256);
  
  client.write(0x81); // text message
  client.write(length | 0x80); // length and mask
  client.write(mask[0]);
  client.write(mask[1]);
  client.write(mask[2]);
  client.write(mask[3]);
  
  int noWrite = 0;
  while (noWrite < length) {
    unsigned char masked = message.charAt(noWrite) ^ mask[noWrite % 4];
    client.write(masked);
    noWrite++;
  }
}

// Run a command when a message is received
void runCommand(Client client, String command) {
  // Change to do what you want here
  sendMessage(client, command); // simple echo
}

void loop()
{
  Client client = server.available();

  if (client) {
    while (client.connected())
    { 
      if (client.available())
      {
        if (!handshakeDone) {
          readHeader(client);
        }
        else {
          String message = readMessage(client);
          runCommand(client, message);
        }
      }
    }

    handshakeDone = false;
    client.flush();
    client.stop();
  }
}



