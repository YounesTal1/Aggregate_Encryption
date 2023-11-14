#include "encryption.h"
#include <string.h>
#include "Global.h"
#include <iostream>

using namespace std;

int main(int argc, char* argv[]) 
{

	FILE *param = fopen("a.param", "r");
        char buff[4096];
        fread(buff, 1, 4096, param);
	printf("System setup Key\n");


	cout << "B = " << B << endl;
	cout << "T = " << T << endl;
	Param pr(buff);


///////////////////////////////////////////////////////////////////////////
//Test:
///////////////////////////////////////////////////////////////////////////

	cout<< "Test: testing Aggregate, Enc, and AggDec" << endl;

	test_agg(pr);


	cout<< "End test with no errors" << endl;
	


}

