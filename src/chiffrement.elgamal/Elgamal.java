package chiffrement.elgamal;

import java.util.Random;
import java.security.SecureRandom;
import java.math.BigInteger;


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
  int x; 

  public Elgamal_SecretKey(BigInteger p, int x)
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

  /*public Elgamal_KeySet()
  {

    this.pkey = new Elgamal_PublicKey();
    this.skey = new Elgamal_SecretKey();
  }*/

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
      if(msg == null)
        throw new Invalid_PlainText();
      else
      {
        int k = params.prg.nextInt(pkey.h.intValue()) + 1;
        BigInteger c1 = pkey.g.pow(k);
        c1 = c1.mod(pkey.p);
        BigInteger c2 = msg.m.multiply(pkey.h.pow(k));
        c2 = c2.mod(pkey.p);
        return new Elgamal_CipherText(c1, c2);
        //encrypt
      }
  }

public Elgamal_PlainText Decrypt(Elgamal_CipherText msg, Elgamal_SecretKey skey) throws Invalid_SecretKey, Invalid_CipherText
{
  if(skey == null)
    throw new Invalid_SecretKey();
  else
    if(msg == null)
      throw new Invalid_CipherText();
    else 
    {
      System.out.println("c1 " + msg.c1);
      System.out.println("c2 " + msg.c2);
      System.out.println("x " + skey.x);
      System.out.println("p " + skey.p);
      System.out.println("pow " + msg.c1.pow(skey.x).mod(skey.p));
      System.out.println("divide " + msg.c2.divide(msg.c1.pow(skey.x).mod(skey.p)));
      BigInteger m = msg.c2.divide(msg.c1.pow(skey.x));
      System.out.println(m.mod(skey.p));
      m = m.mod(skey.p);
      return new Elgamal_PlainText(m);
      //decrypt
    }
}

public Elgamal_KeySet KeyGen()
{
  //Random generator = new Random();
  BigInteger p = getPrime(params.nb_bits, 5, params.prg);
  //BigInteger p2 = p.subtract(BigInteger.ONE);
  //p2 = p2.divide(new BigInteger("2"));
  //System.out.println(p+" "+p2);
  BigInteger g = new BigInteger(params.nb_bits, params.prg);
  g = g.mod(p);
  System.out.println(p.intValue());
  int x = params.prg.nextInt(p.intValue()) + 1;
  BigInteger h  = g.pow(x).mod(p);
  return new Elgamal_KeySet(new Elgamal_PublicKey(p, g, h), new Elgamal_SecretKey(p, x));

  //System.out.println(g + "  " + g.multiply(g) + "  " + g.pow(p2.intValue()) + "  " + g.pow(p2.intValue()*2));
  //System.out.println(order(g, p));
}

public static BigInteger getPrime(int nb_bits, int certainty, Random prg)
{
  while(true)
  {
    BigInteger p = new BigInteger(nb_bits, certainty, prg);
    if(p.signum() == -1)
    {
      //System.out.println(p);
      p = p.negate();
    }
    BigInteger q = p.subtract(BigInteger.ONE);
      //System.out.println(q);
    q = q.divide(new BigInteger("2"));
      //System.out.println(q);
    if(q.isProbablePrime(certainty))
      return p;
  } 
}

public static BigInteger order(BigInteger a, BigInteger n)
{
    //System.out.println(a.intValue());
  for(int i = 1; i<n.intValue(); ++i)
  {
      //System.out.println(i);
    if(((a.pow(i)).mod(n)).equals(BigInteger.ONE))
    {
      BigInteger o = BigInteger.valueOf(i);
        //System.out.println(i);
      return o;
    }
  }
  return BigInteger.ZERO;
}

public static void main(String [] args)
{
  /*Random generator = new Random();
  BigInteger p = getPrime(Integer.parseInt(args[0]), 50, generator);
  BigInteger p2 = p.subtract(BigInteger.ONE);
  p2 = p2.divide(new BigInteger("2"));
    //System.out.println(p+" "+p2);
  BigInteger g = new BigInteger(Integer.parseInt(args[0]), generator);
  g = g.mod(p);
    //System.out.println(g + "  " + g.multiply(g) + "  " + g.pow(p2.intValue()) + "  " + g.pow(p2.intValue()*2));
  System.out.println(order(g, p));*/
  
  Random generator = new Random();
  Elgamal scheme = new Elgamal(Integer.parseInt(args[0]), generator);
  Elgamal_PlainText plain = new Elgamal_PlainText(new BigInteger(Integer.parseInt(args[0]), generator));
  Elgamal_KeySet kset = scheme.KeyGen();
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