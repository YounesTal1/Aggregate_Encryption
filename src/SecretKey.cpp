#include <cassert>
#include "SecretKey.h"
#include "Param.h"
#include "Global.h"
#include <pbc/pbc_field.h>
#include <iostream>
#include <vector>

using namespace std;

SecretKey::SecretKey(){};

SecretKey::SecretKey(Param& pr, element_t& id)
{


   element_init_Zr(this->id, pr.getPairing());
   element_set(this->id, id);
   element_t tmp, tmp2;
   element_init_Zr(tmp, pr.getPairing());
   element_init_G1(tmp2, pr.getPairing());
   element_add(tmp, pr.getAlpha(), id);
   element_invert(tmp, tmp);
   element_pow_zn(tmp2, pr.getGenerator(), tmp);
   element_init_G1(this->sk, pr.getPairing());
   element_set(this->sk, tmp2);



   element_clear(tmp);
   element_clear(tmp2);
}

element_t& SecretKey::getSk()
{
	return this->sk; 
}

element_t& SecretKey::getId()
{
	return this->id; 
}

//DPP taken from "Cécile Delerablée, Pascal Paillier, and David Pointcheval. Fully collusion secure dynamic broadcast encryption with constant-size ciphertexts or decryption keys". 
//Note that this algorithm requires that the messages it is operating over are pairwise distinct, while there is no check in the code to guarantee this. This is not likely to happen as the messages are generated at random from Zr

void DPP(element_t result, int l, std::vector<element_t> &sks, std::vector<element_t> &ids, element_t g, pairing_t pairing)
  {
          element_t tmp, tmp2;
          element_init_Zr(tmp, pairing);
          element_init_G1(tmp2, pairing);
          std::vector<element_t> Powers(l);
          for (int i = 0; i < l; i++) 
          {
            element_init_G1(Powers[i], pairing);
            element_set(Powers[i], sks[i]);
          }
  
          for (int i = 0; i < l - 1; i++)
          {
                  for(int j = i + 1; j < l ; j++)
                  {
                          if ( i != j )
                          {
                                  element_sub(tmp, ids[j], ids[i]);
                                  element_invert(tmp, tmp);
                                  element_sub(tmp2, Powers[i], Powers[j]);
                                  element_pow_zn(Powers[j], tmp2, tmp); 
                          }
                  }
          }
          element_set(result, Powers[l-1]);
          element_clear(tmp);
          element_clear(tmp2);
          for (int j = 0; j < l; j++) 
          {                                                                                                         
                 element_clear(Powers[j]);                                                                                                         
          }
  }


void Aggregate(element_t aggkey, int l, SecretKey *keys, Param& pr)
{
	std::vector<element_t> ids(l);
	std::vector<element_t> sks(l);
	for(int i = 0; i < l; i++)
	{
		element_init_Zr(ids[i], pr.getPairing());
		element_init_G1(sks[i], pr.getPairing());
		element_set(ids[i], keys[i].getId());
		element_set(sks[i], keys[i].getSk());
	}

	DPP(aggkey, l, sks, ids, pr.getGenerator(), pr.getPairing());


}

void CalculateCoeffOmit(int index, element_t *ids, int l, Param& pr, element_t* coeffs) {
    element_t tmp;
    for (int i = 0; i < l; i++) 
    {
        element_init_Zr(coeffs[i], pr.getPairing());
        element_set0(coeffs[i]);
    }

    element_set1(coeffs[0]);
    element_init_Zr(tmp, pr.getPairing());

    for (int i = 0; i < l; i++) 
    {
        if (index != i) {
            element_t* newCoeffs = new element_t[l]; 

            for (int j = 0; j < l; j++) {
                element_init_Zr(newCoeffs[j], pr.getPairing());
                element_set0(newCoeffs[j]);
            }

            for (int j = 0; j < l - 1; j++) {

                element_add(newCoeffs[j + 1], newCoeffs[j + 1], coeffs[j]);
                element_mul(tmp, ids[i], coeffs[j]);
                element_add(newCoeffs[j], newCoeffs[j], tmp);
            }

            for (int j = 0; j < l; j++) 
	    {
		element_set(coeffs[j], newCoeffs[j]);
                element_clear(newCoeffs[j]);
            }
            delete[] newCoeffs;

        }
    }


    element_clear(tmp);

}


void AggDecrypt(element_t decryption, element_t aggkey, element_t *ids, int l, element_t *ct1, element_t ct2, int index, Param& pr)
{

      element_t* coeffs = new element_t[l];
      for (int i = 0; i < l; ++i) 
      {
            element_init_Zr(coeffs[i], pr.getPairing());  
      }

      CalculateCoeffOmit(index, ids, l, pr, coeffs);
      element_t tmp, tmp2;
      element_init_G1(tmp, pr.getPairing());
      element_init_G1(tmp2, pr.getPairing());
      element_set1(tmp2);

      for(int i = 0; i < l; i++)
      {
	      element_pow_zn(tmp, ct1[i], coeffs[i]);
	      element_mul(tmp2, tmp2, tmp);
      }
      element_t v1;
      element_init_GT(v1, pr.getPairing());

      pairing_apply(v1, aggkey, tmp2, pr.getPairing());
      element_invert(v1, v1);
      element_mul(decryption, v1, ct2);

      element_clear(tmp);
      element_clear(tmp2);
      delete[] coeffs;
      
}


