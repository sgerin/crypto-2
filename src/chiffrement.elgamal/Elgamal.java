package chiffrement.elgamal;

import java.util.Random;
import java.security.SecureRandom;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
//import chiffrement.inter.*;



interface CipherScheme
{ 

}


interface Parameters
{
}


interface PublicKey
{

}


interface SecretKey
{

}


interface KeySet
{

}


interface PlainText
{

}


interface CipherText
{

}



class Elgamal_PublicKey implements PublicKey
{
  BigInteger p; 
  BigInteger g; 
  BigInteger h; 

  public Elgamal_PublicKey(BigInteger p, BigInteger g, BigInteger h)
  {
    this.p = p;
    this.g = g; 
    this.h = h;
  }
}


class Elgamal_SecretKey implements SecretKey
{
  BigInteger p;
  BigInteger x; 

  public Elgamal_SecretKey(BigInteger p, BigInteger x)
  {
    this.p = p;
    this.x = x;
  }
}


class Elgamal_KeySet implements KeySet
{
  Elgamal_PublicKey pkey;
  Elgamal_SecretKey skey;

  public Elgamal_KeySet(Elgamal_PublicKey pkey, Elgamal_SecretKey skey)
  {
    this.pkey = pkey;
    this.skey = skey;
  }

}


class Elgamal_PlainText /*extends BigInteger*/ implements PlainText 
{
  BigInteger m;
  Elgamal_PlainText(BigInteger m)
  {
    this.m = m;
  }
}


class Elgamal_CipherText implements CipherText
{
  BigInteger c1; 
  BigInteger c2;

  Elgamal_CipherText(BigInteger c1, BigInteger c2)
  {
    this.c1 = c1;
    this.c2 = c2;
  }
}


class Elgamal_Parameters implements Parameters
{
  int nb_bits; 
  Random prg; 

  public Elgamal_Parameters(int nb_bits, Random prg)
  {
    this.nb_bits = nb_bits; 
    this.prg = prg;
  }

  public Elgamal_Parameters(int nb_bits)
  {
    this.nb_bits = nb_bits; 
    prg = new SecureRandom();
  }
}

class Invalid_PublicKey extends Exception
{
 public Invalid_PublicKey()
 {
   super("Invalid public key");
 }
}

class Invalid_SecretKey extends Exception
{
  public Invalid_SecretKey()
  {
   super("Invalid secret key");
 }
}

class Invalid_PlainText extends Exception
{
 public Invalid_PlainText()
 {
   super("Invalid plain text");
 }
}

class Invalid_CipherText extends Exception
{
  public Invalid_CipherText()
  {
   super("Invalid cipher text");
 }
}


public class Elgamal implements CipherScheme
{

  Elgamal_Parameters params;

  public Elgamal(int nb_bits)
  {
    params = new Elgamal_Parameters(nb_bits);
  }

  public Elgamal(int nb_bits, Random prg)
  {
    params = new Elgamal_Parameters(nb_bits, prg);
  }


  public Elgamal_Parameters getParameters()
  {
    return params;
  }

  public Elgamal_CipherText Encrypt(Elgamal_PlainText msg, Elgamal_PublicKey pkey) throws Invalid_PublicKey, Invalid_PlainText
  { 
    if(pkey == null)
      throw new Invalid_PublicKey();
    else
    {
      if(msg == null)
        throw new Invalid_PlainText();
      else
      {
        System.out.println("h " + pkey.h);
        System.out.println("g " + pkey.g);
        BigInteger k;
        do {
          k = new BigInteger(pkey.h.bitLength(), params.prg);
        } while (k.compareTo(pkey.h) >= 0);

        k = k.add(BigInteger.ONE);

        System.out.println("k " + k);
        BigInteger c1 = pkey.g.modPow(k, pkey.p);
        BigInteger c2 = msg.m.multiply(pkey.h.modPow(k, pkey.p));
        c2 = c2.mod(pkey.p);
        return new Elgamal_CipherText(c1, c2);
      }
    }
  }

  public Elgamal_PlainText Decrypt(Elgamal_CipherText msg, Elgamal_SecretKey skey) throws Invalid_SecretKey, Invalid_CipherText
  {
    if(skey == null)
      throw new Invalid_SecretKey();
    else
    {
      if(msg == null)
        throw new Invalid_CipherText();
      else 
      {
        System.out.println("c1 " + msg.c1);
        System.out.println("c2 " + msg.c2);
        System.out.println("x " + skey.x);
        System.out.println("p " + skey.p);
        System.out.println("pow " + msg.c1.modPow(skey.x, skey.p));
        System.out.println("divide " + msg.c2.divide(msg.c1.modPow(skey.x, skey.p)));
        BigInteger m1 = msg.c1.modPow(skey.x, skey.p);
        BigInteger m2 = m1.modInverse(skey.p);
        BigInteger m = m2.multiply(msg.c2).mod(skey.p);
        return new Elgamal_PlainText(m);
      //decrypt
      }
    }
  }

  public Elgamal_KeySet KeyGen()
  {
  //Random generator = new Random();
    BigInteger p = getPrime(params.nb_bits, 1, params.prg);
    System.out.println("keygen " + p);
    BigInteger p2 = p.subtract(BigInteger.ONE);
    p2 = p2.divide(new BigInteger("2"));
    System.out.println(p+" "+p2);
    BigInteger g = new BigInteger(params.nb_bits, params.prg);
    g = g.mod(p);
    while(g.modPow(p2,p).compareTo(p.subtract(BigInteger.ONE)) != 0)
    {
      g = new BigInteger(params.nb_bits, params.prg);
      g = g.mod(p);
    }
    System.out.println("generator " + g + " pow " + g.modPow(p2,p));
    
        BigInteger x;
        do {
          x = new BigInteger(p.bitLength(), params.prg);
        } while (x.compareTo(p) >= 0);
        x = x.add(BigInteger.ONE);
    
    System.out.println("negative exponent fuck " + x);
    BigInteger h = g.modPow(x,p);
    return new Elgamal_KeySet(new Elgamal_PublicKey(p, g, h), new Elgamal_SecretKey(p, x));

  }

  public static BigInteger getPrime(int nb_bits, int certainty, Random prg)
  {
    while(true)
    {
      BigInteger p = new BigInteger(nb_bits, certainty, prg);
      if(p.signum() == -1)
      {
        p = p.negate();
      }
      BigInteger q = p.multiply(new BigInteger("2"));
      q = q.add(BigInteger.ONE);
      if(q.isProbablePrime(certainty))
        return q;
    } 
  }

  public static BigInteger order(BigInteger a, BigInteger n)
  {
    for(BigInteger i = BigInteger.ONE; i.compareTo(n) < 0; i.add(BigInteger.ONE))
    {
      if((a.modPow(i,n)).equals(BigInteger.ONE))
      {
        return i;
      }
    }
    return BigInteger.ZERO;
  }

  public static void main(String [] args)
  {

  //UNCOMMENT ALL UNDER THIS LINE

  Random generator = new Random();
  Elgamal scheme = new Elgamal(Integer.parseInt(args[0]), generator);
  Elgamal_KeySet kset = scheme.KeyGen();
  Elgamal_PlainText plain = new Elgamal_PlainText(new BigInteger(Integer.parseInt(args[0]), generator).mod(kset.pkey.p));



  try
  {
    Elgamal_CipherText ctext = scheme.Encrypt(plain, kset.pkey);
    Elgamal_PlainText plain2 = scheme.Decrypt(ctext, kset.skey);
    System.out.println("plain1 " + plain.m);
    System.out.println("cipher1 & 2 " + ctext.c1 + "    "+ ctext.c2);
    System.out.println("plain2 " + plain2.m);
  }
  catch(Invalid_CipherText e)
  {

  }
  catch(Invalid_PlainText e)
  {

  }
  catch(Invalid_PublicKey e)
  {

  }
  catch(Invalid_SecretKey e)
  {

  }


  }
}
  