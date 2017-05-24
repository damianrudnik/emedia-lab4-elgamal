#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <gmpxx.h> // duze liczby
#include <ctime>
#include <cmath>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <limits.h>
#include <vector>

using namespace std;
double t;// czas wykonywania algorytmu 
//--do generowania liczb losowych----//
static gmp_randclass r (gmp_randinit_default);
 
static gmp_randstate_t r_state;
//----------------------------------//

typedef mpz_class bi;

typedef struct {
    bi p;	    /* prime */
    bi g;	    /* group generator */
    bi y;	    /* g^x mod p */
} public_key;

typedef struct {
    bi p;	    /* prime */
    bi g;	    /* group generator */
    bi y;	    /* g^x mod p */
    bi x;	    /* secret exponent */
} secret_key;

typedef struct {
    bi S;
    bi R;
} cipher;

static int wiener_map(int);
bi generate_k(bi &);
void generateKey(int, secret_key&);
void encrypt(cipher &, bi &, public_key &);
void decrypt(bi &, cipher&, secret_key &);
bi string2bi(string, unsigned int);
bi char2bi(char *);
char bi2char(bi);
string bi2string_raw(bi&, unsigned int);
string bi2string(bi&, unsigned int, unsigned int);
string getErrorMessage(int);
string ReadFile(string);    //read whole file
string ReadFileSW(string);  //single word
bool WriteToFile(string, string);
bool WriteToBinFile(string, string);
void intime(){ 
  t=clock();
}
void showtime(){ 
  t=clock()-t; 
  cout <<"\nWszystkie operacje zajely: " << ((double)t)/CLOCKS_PER_SEC << " s.\n\n";
}

void bi2v(bi&, unsigned int, vector<uint8_t>&);
void wys_w(vector<uint8_t>& v){
    for (size_t i=0;i<v.size();i++)
        cout<<v[i];
    cout<<endl;
}

void wys_wbi(vector<bi> v) {
    cout << "Wektor ma rozmiar: " << v.size() << ", a miesci w sobie: >>";
    while (!v.empty()){
        cout<<bi2char(v.back());
        v.pop_back();
    }
    cout << "<< koniec"<< endl;
}

void menu(){
    cout << " \nMenu:\n";
    cout << " g. Generate keys\n";
    cout << " 0. Write phrase to the binary file\n";
    cout << " 1. Read binary files\n";
    cout << " 2. Encrypt binary file\n";
    cout << " 3. Decrypt binary file\n";
    cout << " x - EXIT\n--- \n";
}

int main(){
    srand(time(0));
    int seed = rand();
    gmp_randinit_default(r_state);
    gmp_randseed_ui(r_state, seed);
    // INITS
    char ccase=0;
    int iKeySize;
    string phrase, line, filename,key="\0",keypub="\0", test;
    unsigned int msg_size;
    secret_key sekret;
    public_key publiczny;
    cipher SR;
    bi testbi, bimessage, bicrypted, bidecrypted, bin;
    vector<bi> v_bimsg, v_bidecrypted; // wektor, w ktorym wiadomosc jest podzielona na bajty, ale takie zlozone z bi
    vector<cipher> v_bicrypted;        
    // main loop
    do{
        menu();
        cin >> ccase;
        switch (ccase){
            case 't': {
                generateKey(512,sekret);
                publiczny.p = sekret.p;
                publiczny.g = sekret.g;
                publiczny.y = sekret.y;

                cout << "The message: "; 
                getline(cin,phrase);
                testbi = string2bi(phrase,phrase.length());
                cout << "msg = " << testbi << endl;

                encrypt(SR, testbi, publiczny);
                decrypt(bimessage, SR, sekret);
                cout << "msg2= " << bimessage << endl;
                break;
            }
            case 'g': {
                cout << "Size of the keys to generate: ";
                cin >> iKeySize;
                intime();// czas generowania kluczy - przy 4096bit ~ 45 sec
                    generateKey(iKeySize,sekret);
                    publiczny.p = sekret.p;
                    publiczny.g = sekret.g;
                    publiczny.y = sekret.y;
                showtime();
                break;
            }
            case '0': {
                cout << "The message: "; 
                getline(cin,phrase);
                WriteToBinFile("dane.in",phrase);
                testbi = string2bi(phrase,phrase.length());
                cout << "<To check> Message as number before write: \t" << testbi << endl;
                vector<uint8_t> w;
                bi2v(testbi,phrase.length(),w);
                cout << "<To check> Number converted to string: ";
                wys_w(w);
                w.clear();
                cout << endl;
                break;
            }
            case '1': {
                //read phrase from binary file
                phrase = ReadFile("dane.in");
                cout << "Read phrase: \t" << phrase << endl;
                msg_size = phrase.length();
                bimessage = string2bi(phrase,msg_size);
                cout << "The message as number: " << bimessage << endl << endl;
                break;
            }
            case '2': {
                intime();
                // szyfrowanie cryptodecrypt(bi base, bi exponent, const bi &modulo)
                vector<uint8_t> v_8msg; // wektor w ktorym wiadomosc jest podzielona na bajty
                bi2v(bimessage,msg_size,v_8msg); // o tutaj dziele to na mniejsze kawaleczki
                mpz_clear(bimessage.get_mpz_t());// usuniecie wiadomosci w formie liczbowej
                char czmienna;

                while (!v_8msg.empty()){ // tutaj zamieniam kazdy bajt z wektora v_8msg na liczbe do v_bimsg
                    czmienna = char(v_8msg.back());
                    v_bimsg.emplace_back(char2bi(&czmienna));
                    v_8msg.pop_back();
                }

                cipher ciph;
                while (!v_bimsg.empty()){// i tutaj kazda z liczb wektora v_bimsg szyfruje
                    encrypt(ciph, v_bimsg.back(), publiczny);
                    v_bicrypted.emplace_back(ciph);
                    v_bimsg.pop_back();
                }

                // czyszczenie niuzywanych zmiennych
                v_8msg.clear();
                v_bimsg.clear();
                //zapis do pliku
                //WriteToFile("out.txt",crypted);
                cout << "crypt done" << endl;
                showtime();
                break;
            }
            case '3':{
                intime();
                //deszyfrowanie
                bi xored2, tempbi3, bisciagniety;
                while (!v_bicrypted.empty()){// sciagam po kolei elementy wektora zaszyfrowanego - najpierw xor z poprzednim, nastepnie deszyfracja
                    decrypt(tempbi3, v_bicrypted.back(), sekret);
                    v_bicrypted.pop_back();
                    v_bidecrypted.emplace_back(tempbi3);
                }
                cout << "## Zdeszyfrowana wiadomosc: ";
                wys_wbi(v_bidecrypted);
                showtime();
                break;
            }
            case 'x':
                cout << "Bye." << endl;
                //gmp_randclear(r_state);// clearing variables is not working idk why
                /*mpz_clear(testbi.get_mpz_t());
                mpz_clear(bipublickey.get_mpz_t());
                mpz_clear(biprivatekey.get_mpz_t());
                mpz_clear(bimessage.get_mpz_t());
                mpz_clear(bicrypted.get_mpz_t());
                mpz_clear(bidecrypted.get_mpz_t());
                mpz_clear(bin.get_mpz_t());*/
                break;
            default :
                cout << "Wrong letter." << endl;
        }
    }while(ccase != 'x');

    return 0;
}

bi string2bi(string phrase, unsigned int size){
    mpz_t z;
    const void * s = phrase.c_str();
    mpz_init(z);
    mpz_import(z, size, 1, sizeof(char), 0, 0,s);
    bi r = bi(z);
    mpz_clear(z);
    return r;
}

bi char2bi(char *phrase){
    mpz_t z;
    const void * s = phrase;
    mpz_init(z);
    mpz_import(z, 1, 1, sizeof(char), 0, 0,s);
    bi r = bi(z);
    mpz_clear(z);
    return r;
}

char bi2char(bi binumber){
    char answer;
    string str = bi2string_raw(binumber,1);
    uint liczba = atoi( str.c_str() );
    answer = '\0'+liczba;
    return answer;
}

string bi2string_raw(bi& binumber, unsigned int size) {
    char * answer = new char[size];
    mpz_get_str(answer,10,binumber.get_mpz_t());
    return answer;
}

void bi2v(bi& binum, unsigned int size, vector<uint8_t>& v) {
    v.resize(size);
    size_t roman = size_t(size);
    size_t *wskroman = &roman;
    mpz_export(&v[0], wskroman, 1, sizeof(uint8_t), 0, 0, binum.get_mpz_t());
}

static int wiener_map(int n) {
    static struct {int p_n, q_n; } t[] =
    {	/*   p	  q	 attack cost */
	{  512, 119 },	/* 9 x 10^17 */
	{  768, 145 },	/* 6 x 10^21 */
	{ 1024, 165 },	/* 7 x 10^24 */
	{ 1280, 183 },	/* 3 x 10^27 */
	{ 1536, 198 },	/* 7 x 10^29 */
	{ 1792, 212 },	/* 9 x 10^31 */
	{ 2048, 225 },	/* 8 x 10^33 */
	{ 2304, 237 },	/* 5 x 10^35 */
	{ 2560, 249 },	/* 3 x 10^37 */
	{ 2816, 259 },	/* 1 x 10^39 */
	{ 3072, 269 },	/* 3 x 10^40 */
	{ 3328, 279 },	/* 8 x 10^41 */
	{ 3584, 288 },	/* 2 x 10^43 */
	{ 3840, 296 },	/* 4 x 10^44 */
	{ 4096, 305 },	/* 7 x 10^45 */
	{ 4352, 313 },	/* 1 x 10^47 */
	{ 4608, 320 },	/* 2 x 10^48 */
	{ 4864, 328 },	/* 2 x 10^49 */
	{ 5120, 335 },	/* 3 x 10^50 */
	{ 0, 0 }
    };
    int i;

    for(i=0; t[i].p_n; i++ )  {
        if( n <= t[i].p_n )
            return t[i].q_n;
    }
    /* not in table - use some arbitrary high number ;-) */
    return  n / 8 + 200;
}

bi generate_k(bi &p) {
    bi k;
    unsigned int pbits = mpz_sizeinbase(p.get_mpz_t(),2);
    unsigned int kbits = wiener_map( pbits ) * 3 / 2;
    mpz_urandomb(k.get_mpz_t(),r_state,kbits);
    cout << "gen_k k=" << k << endl;
    return k;
}

void generateKey(int size, secret_key& key){
    bi p;
    bi g = mpz_class(1);
    bi x;
    bi y;
    bi tmp;
    int qbits, xbits;

    // p calculation
	bool prime = false;
    while(!prime){
		p = r.get_z_bits(size);
		int isPrime = 1;
		isPrime = mpz_probab_prime_p(p.get_mpz_t(), 25);
	    if(isPrime != 0) break;
	}
    // g calculation
    qbits = wiener_map(size);
    if( qbits & 1 )	qbits++; //aby byly nieparzyste
    
    prime = false;
    while(!prime){
        mpz_urandomb(g.get_mpz_t(),r_state,qbits);
		int isPrime = 1;
		isPrime = mpz_probab_prime_p(g.get_mpz_t(), 25);
	    if(isPrime != 0) break;
	}
    // x calculation
    size--;// rozmiar nie moze byc wiekszy niz rozmiar p
    xbits = rand() % size + qbits;
    mpz_urandomb(x.get_mpz_t(),r_state,xbits);
    
    // y calculation
    mpz_powm (y.get_mpz_t(), g.get_mpz_t(), x.get_mpz_t(), p.get_mpz_t()); // obliczanie y
    cout << "elg p= " << p << "\n";
    cout << "elg g= " << g << "\n";
    cout << "elg y= " << y << "\n";
    cout << "elg x= " << x << "\n\n";

    key.p = p;
    key.g = g;
    key.y = y;
    key.x = x;
}

void encrypt(cipher &c, bi &msg, public_key &pkey) {
    bi k;
    k = generate_k(pkey.p);
    mpz_powm (c.S.get_mpz_t(), pkey.g.get_mpz_t(), k.get_mpz_t(), pkey.p.get_mpz_t());
    mpz_powm (c.R.get_mpz_t(), pkey.y.get_mpz_t(), k.get_mpz_t(), pkey.p.get_mpz_t());
    mpz_mul (c.R.get_mpz_t(),c.R.get_mpz_t(),msg.get_mpz_t()); 
    mpz_mod (c.R.get_mpz_t(),c.R.get_mpz_t(),pkey.p.get_mpz_t());
}

void decrypt(bi &msg, cipher &c, secret_key &skey) {
    bi temp;
    // msg = R/(S^x) mod p
    mpz_powm (temp.get_mpz_t(), c.S.get_mpz_t(), skey.x.get_mpz_t(), skey.p.get_mpz_t());
    mpz_invert(temp.get_mpz_t(), temp.get_mpz_t(), skey.p.get_mpz_t());
    mpz_mul (msg.get_mpz_t(), c.R.get_mpz_t(), temp.get_mpz_t());
    mpz_mod (msg.get_mpz_t(),msg.get_mpz_t(),skey.p.get_mpz_t());
}

string ReadFile(string filename){
    int length;
    string phrase;
    ifstream file (filename, ios::in|ios::binary|ios::ate);
    if (file.is_open()){
        //file.seekg(0,file.end);
        length = file.tellg();
        length = length - 4; //przesuniecie o 4 znaki: "^C^@^@^@", ktore sa wpisywane na poczatku pliku binarnego
        file.seekg (4,file.beg);
        char * buffer = new char [length];
        cout << "Zczytano " << length << " znakow.\n";
        file.read(buffer,length);
        phrase.assign(buffer,length);
        file.close();
        return phrase;
    }else {
        cerr << "Nie moge otworzyc pliku " << filename << endl; 
        return getErrorMessage(10); 
    }
}

string getErrorMessage(int errorCode){
    static map<int, string> codes;
    static bool initialized = false;
    if (!initialized) {
        codes[0]    = "No error.";
        codes[1]    = "Create error.";
        codes[10]   = "Read error.";
        codes[40]   = "Network or protocol error.";
        initialized = true;
    }
    if (codes.count(errorCode) > 0)
        return codes[errorCode];
    return "Unknown error.";
}

string ReadFileSW(string filename){
    string phrase, line;
    ifstream file (filename);
    if (file.is_open()){
        /*while (*/getline (file,line);// ){
            istringstream dane(line);
            dane >> phrase;//}
        file.close();
        return phrase;
    }else {
        return getErrorMessage(10); 
    }
}

bool WriteToFile(string filename, string phrase){
    int length = phrase.length();
    ofstream encodefile (filename, ios::trunc);
    if (encodefile.is_open()){
        char * buffer = new char [length];
        strcpy(buffer,phrase.c_str());
        encodefile.write(buffer,length);
        delete[] buffer;
        encodefile.close();
        cout << "Zapisano do pliku " << filename<<endl<<endl;
        return true;
    }else {
        cerr << "Nie moge otworzyc pliku " << filename << endl; 
        return false;
    }
}

bool WriteToBinFile(string filename, string phrase){
    int length = phrase.length();
    cout << endl << "Rozmiar: " << length << endl;
    ofstream encodefile (filename, ios::out | ios::trunc | ios::binary);
    if (encodefile.is_open()){
        encodefile.write(reinterpret_cast<char *>(&length),sizeof(int));
        encodefile.write(phrase.c_str(),length);
        encodefile.flush();
        encodefile.close();
        cout << "Zapisano do pliku " << filename<<endl;
        return true;
    }else {
        cerr << "Nie moge otworzyc pliku " << filename << endl; 
        return false;
    }
}
