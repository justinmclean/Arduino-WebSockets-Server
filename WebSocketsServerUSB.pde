#include <sha1.h>
#include <Base64.h>

const char hex[] ="0123456789abcdef";

boolean websocket = false;
boolean handshakeDone = false;
String key;

void setup()
{
  pinMode(3,OUTPUT);
  pinMode(5,OUTPUT);
  pinMode(6,OUTPUT);
  Serial.begin(57600);
}

// Read a line at a time
String readLine()
{
  String data;
  boolean lineEnd = false;

  while (!lineEnd) 
  {
    if (Serial.available()) {
      char c = Serial.read();
      digitalWrite(6, HIGH);
      delay(100);
      digitalWrite(6  , LOW);
      
      if (c != '\n' && c != '\r') {
        data.concat(c);
      }
      if (c == '\n') {
        digitalWrite(3, HIGH);
        delay(100);
        digitalWrite(3, LOW);
        lineEnd = true;
      }
    }
  }
  
   return data;
}

// Return true is line is "blank"
boolean blankLine(String line) {
  return (line.length() == 0);
}

// Send a standard http response header
void httpOK() {
  Serial.println("HTTP/1.1 200 OK");
  Serial.println("Content-Type: text/html");
  Serial.println();
}

// Send a header to switch to the web sockets protocol
void webSocketOK(String key) {
  Serial.println("HTTP/1.1 101 Switching Protocols");
  Serial.println("Upgrade: websocket");
  Serial.println("Connection: Upgrade");
  Serial.print("Sec-WebSocket-Accept: ");
  Serial.println(key);
  Serial.println();
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
void readHeader() {
  String line = readLine(); 
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
      webSocketOK(encode);
      handshakeDone = true;
      digitalWrite(5, HIGH);
      delay(100);
      digitalWrite(5, LOW);
    }
    else {
      httpOK();
    }
  }
}

// read and decode a web socket message
String readMessage()
{
  String data;
  unsigned char opcode;
  unsigned char length;
  boolean useMask;
  unsigned char mask[4];

  opcode = Serial.read();
  //TODO check opcode
  length = Serial.read();
  useMask = ((length & 0x80) == 0x80);
  length = length & 0x7F;
  if (useMask) {
    mask[0] = Serial.read();
    mask[1] = Serial.read();
    mask[2] = Serial.read();
    mask[3] = Serial.read();
  }

  int noRead = 0;  
  while (noRead < length) 
  {
    unsigned char masked = Serial.read();

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
void sendMessage(String message) {
  unsigned char mask[4];
  int length = message.length();
  
  mask[0] = random(256);
  mask[1] = random(256);
  mask[2] = random(256);
  mask[3] = random(256);
  
  Serial.write(0x81); // text message
  Serial.write(length | 0x80); // length and mask
  Serial.write(mask[0]);
  Serial.write(mask[1]);
  Serial.write(mask[2]);
  Serial.write(mask[3]);
  
  int noWrite = 0;
  while (noWrite < length) {
    unsigned char masked = message.charAt(noWrite) ^ mask[noWrite % 4];
    Serial.write(masked);
    noWrite++;
  }
}

// Run a command when a message is received
void runCommand(String command) {
  // Change to do what you want here
  sendMessage(command); // simple echo
}

void loop()
{
    while (Serial.available())
    {
      if (!handshakeDone) {
        readHeader();
      }
      else {
        String message = readMessage();
        runCommand(message);
      }
    }

    handshakeDone = false;
}

