#include "Param.h"
#include "Global.h"


int B = 50;
//T has to be smaller than B
int T = 40;
Param::Param(){}

Param::Param(const char *pstr):  pk(nullptr)
{
	pk = new element_t[B];
	this->pstr = pstr;
	pairing_init_set_str(this->pairing, pstr);
	element_init_G1(this->g, this->pairing);
	element_random(this->g);
	element_init_Zr(this->alpha, this->pairing);
	element_random(this->alpha);
	element_init_G1(this->pk[0], this->pairing);
	element_pow_zn(this->pk[0],  this->g, this->alpha);
	for (int i = 1; i < B; i++)
	{
		element_init_G1(this->pk[i], this->pairing);
		element_pow_zn(this->pk[i], this->pk[i-1], alpha);
	}
}

element_t* Param::getPk()
{
	return this->pk;
}

pairing_t& Param::getPairing()
{
	return this->pairing;
}

const char* Param::getPstr()
{
	return this->pstr;
}


element_t& Param::getAlpha()
{
	return this->alpha;
}

element_t& Param::getGenerator()
{ 
	return this->g; 
}

