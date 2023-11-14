#ifndef _SecretKey_h
#define _SecretKey_h  
  

#include <pbc/pbc.h>
#include "Param.h"
#include <vector>
  
class SecretKey {
public:

    SecretKey();
    SecretKey(Param& pr, element_t& id);
    element_t& getSk();
    element_t& getId();

private:
    element_t id;
    element_t sk;
};




void CalculateCoeffOmit(int index, element_t *ids, int l, Param& pr, element_t* coeffs);
void Aggregate(element_t aggkey, int l, SecretKey *keys, Param& pr);
void DPP(element_t result, int l, std::vector<element_t> &sks, std::vector<element_t> &ids, element_t g, pairing_t pairing);
void AggDecrypt(element_t decryption, element_t aggkey, element_t *ids, int l, element_t *ct1, element_t ct2, int index, Param& pr);

element_t& AggKey(element_t aggkey, std::vector<SecretKey> &keys);  
  
#endif  

