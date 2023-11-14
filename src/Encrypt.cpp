#include "Encrypt.h"
#include "SecretKey.h"
#include "Global.h"
#include "Param.h"
#include <pbc/pbc_field.h>
#include <iostream>
#include <cassert>


using namespace std;

Encrypt::Encrypt(){};

Encrypt::Encrypt(element_t& id, element_t& message, element_t *pk, pairing_t& pairing, element_t& g): ct1(nullptr)
{

    element_t r, rid, tmp, tmp2;
    element_init_Zr(r, pairing);
    element_init_Zr(rid, pairing);
    element_init_G1(tmp, pairing);
    element_init_G1(tmp2, pairing);

    element_random(r);
    element_mul(rid, r, id);

    element_pow_zn(tmp, pk[0], r);
    element_pow_zn(tmp2, g, rid);

    ct1 = new element_t[T+1];
    element_init_G1(ct1[0], pairing);
    element_mul(ct1[0], tmp, tmp2);

    for (int i = 1; i < T+1; i++)
    {
	element_pow_zn(tmp, pk[i], r);
	element_pow_zn(tmp2, pk[i-1], rid);
        element_init_G1(ct1[i], pairing);
	element_mul(ct1[i], tmp, tmp2);

    }
    element_init_GT(ct2, pairing);
    element_t v1, temp;
    element_init_GT(v1, pairing);
    element_init_GT(temp, pairing);
    pairing_apply(v1, g, g, pairing);
    element_pow_zn(temp, v1, r);
    element_mul(ct2, temp, message);


    element_clear(r);
    element_clear(rid);
    element_clear(temp);
    element_clear(tmp);
    element_clear(tmp2);
    

}
element_t* Encrypt::getCt1()
{
         return this->ct1;
}

element_t& Encrypt::getCt2()
{
          return this->ct2;
}
 


