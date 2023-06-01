#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <fstream>
#include <cstdint>

using namespace std;

#define MAX_BUF_LEN 65536

#pragma comment(lib, "ws2_32.lib") // Librería de winsock

unsigned char *readName(unsigned char *, unsigned char*, int*);

bool searchInMasterFile(unsigned char *, unsigned char *);

void ChangetoDnsNameFormat(unsigned char* ,unsigned char*);

struct DNS_HEADER
{
  unsigned short id; // identification number

  unsigned char rd :1; // recursion desired
  unsigned char tc :1; // truncated message
  unsigned char aa :1; // authoritive answer
  unsigned char opcode :4; // purpose of message
  unsigned char qr :1; // query/response flag

  unsigned char rcode :4; // response code
  unsigned char cd :1; // checking disabled
  unsigned char ad :1; // authenticated data
  unsigned char z :1; // its z! reserved
  unsigned char ra :1; // recursion available

  unsigned short q_count; // number of question entries
  unsigned short ans_count; // number of answer entries
  unsigned short auth_count; // number of authority entries
  unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
#pragma (push, 1)
struct QUESTION
{
  unsigned short qtype;
  unsigned short qclass;
};
#pragma (pop)

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
  unsigned short type;
  unsigned short _class;
  unsigned int ttl;
  unsigned short data_len;
};
#pragma pack(pop)
//Pointers to resource record contents
struct RES_RECORD
{
  unsigned char *name;
  struct R_DATA *resource;
  unsigned char *rdata;
};

//Structure of a Query
struct QUERY
{
  unsigned char *name;
  struct QUESTION *ques;
};

#pragma pack(push, 1)
struct RES_NAME_POINTER {
  unsigned short pointer;
  unsigned short type;
  unsigned short _class;
  unsigned long ttl;
  unsigned short data_len;
  unsigned char addressOne;
  unsigned char addressTwo;
  unsigned char addressThree;
  unsigned char addressFour;
};
#pragma pack(pop)

int main() {

  WSADATA firstsock;
  cout << "\nInicializando Winsock...";
  if (WSAStartup(MAKEWORD(2, 2), &firstsock) != 0) {
    cout << "Ups, algo ha fallado con Winsock : " << WSAGetLastError();
    return 1;
  }

  cout << "Inicializado!\n";

  SOCKET serverSocket;
  sockaddr_in a, dest;

  a.sin_family = AF_INET; // Usamos IP version 4
  // https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-htons
  a.sin_port = htons(53); // Usamos el puerto 53
  a.sin_addr.s_addr = INADDR_ANY; // Vamos a usar la direccion que este disponible

  dest.sin_family = AF_INET;
  dest.sin_port = htons(53);

  // Creacion del socket
  serverSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  // Bindear el socket
  bind(serverSocket, (sockaddr *)&a, sizeof(a));

  while (true) {
    unsigned char buffer[MAX_BUF_LEN];
    int i = sizeof(dest);
    cout << "\nRecibiendo peticiones...";

    // Recibir el mensaje, la informacion del socket entrante se almacena dest
    int bytesIncoming = recvfrom(serverSocket, (char *)buffer, MAX_BUF_LEN, 0, (struct sockaddr*)&dest, &i);
    if ( bytesIncoming == SOCKET_ERROR) {
      cout << "Ups, ocurrió un error" << WSAGetLastError();
    }

    cout << "Recibido.";

    string clientIP = inet_ntoa(dest.sin_addr);

    if (clientIP == "10.2.1.10") {
      continue;
    }

    // Importante moverse entre las direcciones de memoria del buffer a medida de que se va leyendo el mismo

    // Aquí indicamos que castee el buffer (char []) como nuestra estructura con los tipos de datos requeridos para manipular los bits
    DNS_HEADER *dnsHeader = nullptr;
    dnsHeader = (DNS_HEADER *)buffer;

    // En este momento dnsHeader ya contiene el header del paquete
    /*
     *      +---------------------+
            |        Header       | <--------- YA (dnsHeader)
            +---------------------+
            |       Question      | the question for the name server
            +---------------------+
            |        Answer       | RRs answering the question
            +---------------------+
            |      Authority      | RRs pointing toward an authority
            +---------------------+
            |      Additional     | RRs holding additional information
            +---------------------+
     * */

    // Ahora vamos a movernos por medio del buffer
    unsigned char *reader;

    /*
     * reader = & -> Direccion de memoria
     *          buffer[sizeof(DNS_HEADER)]; Del buffer en la posicion despues de leer del DNS
     * */
    reader = &buffer[sizeof(DNS_HEADER)];

    // reader en este momento tiene toodo el buffer menos el header

    /*
     *      +---------------------+
            |        Header       | <--------- YA (dnsHeader)
            +---------------------+ <---- reader esta acá
            |       Question      | the question for the name server
            +---------------------+
            |        Answer       | RRs answering the question
            +---------------------+
            |      Authority      | RRs pointing toward an authority
            +---------------------+
            |      Additional     | RRs holding additional information
            +---------------------+
     * */

    cout << "\nEl paquete entero contiene: ";

    // https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-ntohs
    cout << "\n " << ntohs(dnsHeader->q_count) << " Preguntas.";
    cout << "\n " << ntohs(dnsHeader->ans_count) << " Respuestas.";
    cout << "\n " << ntohs(dnsHeader->auth_count) << " Servidores autoritarios.";
    cout << "\n " << ntohs(dnsHeader->add_count) << " Records adicionales.";

    int stop = 0;

    QUERY queries[20];
    for (int j = 0; j < ntohs(dnsHeader->q_count); j++) {
      queries[j].name = readName(reader, buffer, &stop);
      // Actualizamos la posición del buffer donde se quedó al guardar el nombre
      reader += stop;
      queries[j].ques = (QUESTION *)(reader);

      reader += sizeof(QUESTION);
      // En este momento reader está comenzando las answers, las cuales no nos interesan hasta que respondamos el paquete
      cout << "\nQuery: " << queries[j].name << endl;
    }

    unsigned char result[256];
    bool found = searchInMasterFile(queries[0].name, result);

    if (found) {
      unsigned char packet[MAX_BUF_LEN];

      DNS_HEADER *dnsResponse;

      dnsResponse = (DNS_HEADER*)&packet;

      dnsResponse->id = dnsHeader->id;
      dnsResponse->qr = 1;
      dnsResponse->opcode = 0;
      dnsResponse->aa = 0;
      dnsResponse->tc = 0;
      dnsResponse->rd = 1;
      dnsResponse->ra = 0;
      dnsResponse->z = 0;
      dnsResponse->ad = 0;
      dnsResponse->cd = 0;
      dnsResponse->rcode = 0;
      dnsResponse->q_count = htons(1);
      dnsResponse->ans_count = htons(1);
      dnsResponse->auth_count = 0;
      dnsResponse->add_count = 0;

      QUESTION*questionCopy;
      unsigned char *questionName;

      questionName = (unsigned char*)&packet[sizeof(DNS_HEADER)];

      ChangetoDnsNameFormat(questionName, queries[0].name);

      questionCopy = (struct QUESTION*)&packet[sizeof(struct DNS_HEADER) + (strlen((const char*)questionName) + 1)];

      questionCopy->qtype = queries[0].ques->qtype;
      questionCopy->qclass = queries[0].ques->qclass;

      RES_NAME_POINTER* answerName;
      answerName = (RES_NAME_POINTER*)&packet[sizeof(struct DNS_HEADER) + (strlen((const char*)questionName)+1) + sizeof(struct QUESTION)];


      answerName->pointer = (htons(49164));

      answerName->type = htons(1);
      answerName->_class = htons(1);
      answerName->ttl = htonl(30);
      answerName->data_len = htons(4);

      // Ensmablar la direccion

      char *l;
      string convert;

      // Primer segmento
      l = strtok((char *)result, ".");

      convert = string(l);

      answerName->addressOne = stoi(convert);

      //Segundo segmento
      l = strtok(NULL, ".");

      convert = string(l);

      answerName->addressTwo = stoi(convert);

      // Tercer segmento
      l = strtok(NULL, ".");

      convert = string(l);

      answerName->addressThree = stoi(convert);

      // Cuarto segmento
      l = strtok(NULL, ".");

      convert = string(l);

      answerName->addressFour = stoi(convert);

      cout << "\nEnviando paquete...";
      if (sendto(serverSocket, (char *)packet, sizeof(struct DNS_HEADER) + (strlen((const char*)questionName)+1) + sizeof(struct QUESTION) + sizeof(RES_NAME_POINTER), 0, (struct sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR) {
        cout << "Error envíando el paquete: " << WSAGetLastError() << endl;
      }

      cout << "Enviado!";
    } else {
      sockaddr_in foreign;

      foreign.sin_family = AF_INET;
      foreign.sin_port = htons(53);
      // DNS de la Javeriana
      foreign.sin_addr.s_addr = inet_addr("10.2.1.10");

      cout << "\nEnviando paquete al DNS de la Javeriana...";

      if (sendto(serverSocket, (char *)buffer, bytesIncoming, 0, (sockaddr *)&foreign, sizeof(foreign)) == SOCKET_ERROR) {
        cout << "Ups, hubo un error con el paquete de la Javeriana: " << WSAGetLastError();
      }

      cout << "Enviado.";

      int newSizeForeign = sizeof(foreign);

      cout << "\nRecibiendo respuesta de la Javeriana...";

      unsigned char incoming[MAX_BUF_LEN];

      int bytesRecieved = recvfrom(serverSocket, (char *)incoming, MAX_BUF_LEN, 0, (sockaddr*)&foreign, &newSizeForeign);

      if (bytesRecieved == SOCKET_ERROR) {
        cout << "Ups, paso algo con la respuesta de la Javeriana " << WSAGetLastError();
      }

      cout << "Recibido!!\n";

      if (sendto(serverSocket, (char *)incoming, bytesRecieved, 0, (sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR) {
        cout << "Ups, paso algo reenviando el mensaje. " << WSAGetLastError();
      }

      DNS_HEADER *incomingHeader;
      incomingHeader = (DNS_HEADER*)incoming;

      // Calcula la posicion de la primera respuesta

      unsigned char *readerIncoming, *newReader;

      newReader = &incoming[sizeof(DNS_HEADER)];

      int countStop = 0;

      unsigned char *nameResolved = readName(newReader, incoming, &countStop);

      newReader += countStop;
      newReader += sizeof(QUESTION);

      /*newReader = &incoming[sizeof(DNS_HEADER) + (strlen((const char*)nameResolved)+1) + sizeof(QUESTION)];*/

      int countStopReader = 0;

      RES_RECORD answers[20];

      for (int h = 0; h < ntohs(incomingHeader->ans_count); h++) {
        answers[h].name = readName(newReader, incoming, &countStopReader);
        newReader += countStopReader;

        answers[h].resource = (R_DATA*)(newReader);

        newReader += sizeof(struct R_DATA);

        if (ntohs(answers[h].resource->type) == 1) {
          // Es una IPV4
          answers[h].rdata = (unsigned char *)malloc(ntohs(answers[h].resource->data_len));

          for (int j = 0; j < ntohs(answers[h].resource->data_len); j++) {
            answers[h].rdata[j] = newReader[j];
          }

          answers[h].rdata[ntohs(answers[h].resource->data_len)] = '\0';

          newReader += ntohs(answers[h].resource->data_len);
        }
      }

      ofstream master("masterFile.txt", ios::app);
      if (!master) {
        cout << "El Master File no pudo ser abierto\n";
      }
      for(i=0;i<ntohs(incomingHeader->ans_count);i++)
      {
        master << "$ORIGIN " << nameResolved << "\n";
        master << "\t\t$INCLUDE masterFile.txt " << nameResolved << "\n";
        master << "\t\t" <<  nameResolved << " " << answers[i].resource->ttl << " " << ((ntohs(answers[i].resource->_class) == 1) ? "IN" : " ") << " " << ((ntohs(answers[i].resource->type) == 1) ? "A" : " ") << " ";
        printf("Dominio : %s ",answers[i].name);

        if(ntohs(answers[i].resource->type)==1) //IPv4 address
        {
          sockaddr_in t;
          long *p;
          p=(long*)answers[i].rdata;
          t.sin_addr.s_addr=(*p); //working without ntohl
          printf("tiene una direccion IPV4 : %s",inet_ntoa(t.sin_addr));
          master << inet_ntoa(t.sin_addr) << "\n\n";
        }
        if(ntohs(answers[i].resource->type)==5) //Canonical name for an alias
        {
          printf("tiene un alias : %s",answers[i].rdata);
        }

        printf("\n");
      }

      master.close();
    }
  }
  return 0;
}

unsigned char *readName(unsigned char *reader, unsigned char *buffer, int *count) {
  unsigned char *name;
  unsigned int p=0,jumped=0,offset;
  int i , j;

  *count = 1;
  name = (unsigned char*)malloc(256);

  name[0]='\0';

  //read the names in 3www6google3com format
  while(*reader!=0)
  {
    if(*reader>=192)
    {
      offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
      reader = buffer + offset - 1;
      jumped = 1; //we have jumped to another location so counting wont go up!
    }
    else
    {
      name[p++]=*reader;
    }

    reader=reader+1;

    if(jumped==0) *count = *count + 1; //if we havent jumped to another location then we can count up
  }

  name[p]='\0'; //string complete
  if(jumped==1)
  {
    *count = *count + 1; //number of steps we actually moved forward in the packet
  }

  //now convert 3www6google3com0 to www.google.com
  for(i=0;i<(int)strlen((const char*)name);i++)
  {
    p=name[i];
    for(j=0;j<(int)p;j++)
    {
      name[i]=name[i+1];
      i=i+1;
    }
    name[i]='.';
  }

  name[i-1]='\0'; //remove the last dot

  return name;
}

bool searchInMasterFile(unsigned char *name, unsigned char *result) {
  ifstream master("masterFile.txt");

  if (!master) {
    cout << "Ups, paso algo abriendo el masterFile\n";
    return false;
  }

  bool found = false, diferente = false;
  char * p, *cop = new char[600];
  int ref = 0;
  while (!master.eof()) {
    master.getline(cop, 600);
    if (cop[0] == '$' && cop[1] == 'O') {
      if (strstr(cop, (char *)name) != NULL) {
        diferente = false;
        p = strtok(cop, " ");
        p = strtok(NULL, " ");
        int i, l=0;
        if (p[0] == 'w' && p[1] == 'w' && p[2] == 'w' && p[3] == '.') {
          i = 4;
        } else {
          i = 0;
        }
        for (; i < strlen(p); i++) {
          if (p[i] != name[l]) {
            diferente = true;
            ref = 0;
            break;
          }
          l++;
        }
        if (diferente) continue;
        found = true;
        ref = 0;
      }
    }
    if (ref == 2 && found) {
      p = strtok(cop, " ");
      int times = 4;
      while (times--) {
        p = strtok(NULL, " ");
      }
      delete [] cop;
      for (int k = 0; k < strlen(p); k++) {
        result[k] = p[k];
      }
      return true;
      break;
    }
    ref++;
  }

  if (!found) {
    return false;
  }

  master.close();

  return false;
}

void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host)
{
  int lock=0 , i;

  strcat((char*)host,".");

  for(i=0 ; i<(int)strlen((char*)host) ; i++)
  {
    if(host[i]=='.')
    {
      *dns++=i-lock;
      for(;lock<i;lock++)
      {
        *dns++=host[lock];
      }
      lock++; //or lock=i+1;
    }
  }
  *dns++='\0';
}