#include <cassert>

#include "Param.h"

#include "SecretKey.h"
#include "Encrypt.h"
#include "Global.h"
#include <list>
#include <iostream>
  
using namespace std;

void test_agg(Param pr)
{
	element_t aggkey;
        element_init_G1(aggkey, pr.getPairing());

	//number of ids l, has to be smaller than T
	int l = 5;
	assert(l < T);
	element_t *ids;                                                                                     
	ids = new element_t[l];

	SecretKey* keys = new SecretKey[l];
        for(int i = 0; i < l ; i++)                                                                                               
        {                                                                                                                         
                element_init_Zr(ids[i], pr.getPairing());                                                                  
		element_random(ids[i]);
		new (&keys[i]) SecretKey(pr, ids[i]);
	}

	Aggregate(aggkey, l, keys, pr);
	int nb_msg = 10;
	element_t message, decryption;
	//Note a message in the case of Encryption is an element of GT as opposed to the signature case, where it lies in G1
	element_init_GT(message, pr.getPairing());                                                                  
	element_init_GT(decryption, pr.getPairing());                                                                  
	for (int i = 0; i < nb_msg; i++)
	{
		element_random(message);
		for (int index = 0; index < l; index++)
		{
			Encrypt ct(ids[index], message, pr.getPk(), pr.getPairing(), pr.getGenerator());
			AggDecrypt(decryption, aggkey, ids, l, ct.getCt1(), ct.getCt2(), index, pr) ;
			bool b = !element_cmp(message, decryption);
			assert(b == 1);
		}
	}

}

