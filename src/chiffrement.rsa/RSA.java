package chiffrement.rsa;

import java.util.Random;
import java.security.SecureRandom;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;



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



class RSA_PublicKey implements PublicKey
{
  BigInteger n; 
  BigInteger e; 

  public RSA_PublicKey(BigInteger n, BigInteger e)
  {
    this.n = n;
    this.e = e; 
  }
}


class RSA_SecretKey implements SecretKey
{
  BigInteger n;
  BigInteger d; 

  public RSA_SecretKey(BigInteger n, BigInteger d)
  {
    this.n = n;
    this.d = d;
  }
}


class RSA_KeySet implements KeySet
{
  RSA_PublicKey pkey;
  RSA_SecretKey skey;

  public RSA_KeySet(RSA_PublicKey pkey, RSA_SecretKey skey)
  {
    this.pkey = pkey;
    this.skey = skey;
  }

  /*public RSA_KeySet()
  {

    this.pkey = new RSA_PublicKey();
    this.skey = new RSA_SecretKey();
  }*/

}


class RSA_PlainText /*extends BigInteger*/ implements PlainText 
{
  BigInteger m;
  RSA_PlainText(BigInteger m)
  {
    this.m = m;
  }
}


class RSA_CipherText implements CipherText
{
  BigInteger c; 

  RSA_CipherText(BigInteger c)
  {
    this.c = c;
  }
}


class RSA_Parameters implements Parameters
{
  int nb_bits; 
  Random prg; 

  public RSA_Parameters(int nb_bits, Random prg)
  {
    this.nb_bits = nb_bits; 
    this.prg = prg;
  }

  public RSA_Parameters(int nb_bits)
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


public class RSA implements CipherScheme
{

  RSA_Parameters params;

  public RSA(int nb_bits)
  {
    params = new RSA_Parameters(nb_bits);
  }

  public RSA(int nb_bits, Random prg)
  {
    params = new RSA_Parameters(nb_bits, prg);
  }


  public RSA_Parameters getParameters()
  {
    return params;
  }

  public RSA_CipherText Encrypt(RSA_PlainText msg, RSA_PublicKey pkey) throws Invalid_PublicKey, Invalid_PlainText
  { 
    if(pkey == null)
      throw new Invalid_PublicKey();
    else
    {
      if(msg == null)
        throw new Invalid_PlainText();
      else
      {

        // System.out.println("h " + pkey.h);
        // System.out.println("g " + pkey.g);
        // BigInteger k;
        // do {
        //   k = new BigInteger(pkey.h.bitLength(), params.prg);
        // } while (k.compareTo(pkey.h) >= 0);

        // k = k.add(BigInteger.ONE);

        // System.out.println("k " + k);
        // BigInteger c1 = pkey.g.modPow(k, pkey.p);

        // BigInteger c2 = msg.m.multiply(pkey.h.modPow(k, pkey.p));
        // c2 = c2.mod(pkey.p);
        // return new RSA_CipherText(c1, c2);
        //encrypt


        BigInteger c = msg.m.modPow(pkey.e, pkey.n);
        return new RSA_CipherText(c);
      }
    }
  }

  public RSA_PlainText Decrypt(RSA_CipherText msg, RSA_SecretKey skey) throws Invalid_SecretKey, Invalid_CipherText
  {
    if(skey == null)
      throw new Invalid_SecretKey();
    else
    {
      if(msg == null)
        throw new Invalid_CipherText();
      else 
      {
        // System.out.println("c1 " + msg.c1);
        // System.out.println("c2 " + msg.c2);
        // System.out.println("x " + skey.x);
        // System.out.println("p " + skey.p);
        // System.out.println("pow " + msg.c1.modPow(skey.x, skey.p));
        // System.out.println("divide " + msg.c2.divide(msg.c1.modPow(skey.x, skey.p)));
        // BigInteger m1 = msg.c1.modPow(skey.x, skey.p);
        // BigInteger m2 = m1.modInverse(skey.p);
        // BigInteger m = m2.multiply(msg.c2).mod(skey.p);
        //BigInteger m = msg.c2.divide(msg.c1.modPow(skey.x, skey.p));
        //System.out.println(m.mod(skey.p));
        //m = m.mod(skey.p);
        // return new RSA_PlainText(m);
      //decrypt
      	BigInteger m = msg.c.modPow(skey.d, skey.n);
      	return new RSA_PlainText(m);
      }
    }
  }

  public RSA_KeySet KeyGen()
  {
    // BigInteger p = getPrime(params.nb_bits, 1, params.prg);
    // System.out.println("keygen " + p);
    // BigInteger p2 = p.subtract(BigInteger.ONE);
    // p2 = p2.divide(new BigInteger("2"));
    // System.out.println(p+" "+p2);
    // BigInteger g = new BigInteger(params.nb_bits, params.prg);
    // g = g.mod(p);
    // while(g.modPow(p2,p).compareTo(p.subtract(BigInteger.ONE)) != 0)
    // {
    //   g = new BigInteger(params.nb_bits, params.prg);
    //   g = g.mod(p);
    // }
    // System.out.println("generator " + g + " pow " + g.modPow(p2,p));
    //     BigInteger x;
    //     do {
    //       x = new BigInteger(p.bitLength(), params.prg);
    //     } while (x.compareTo(p) >= 0);
    //     x = x.add(BigInteger.ONE
    // System.out.println("negative exponent fuck " + x);
    // BigInteger h = g.modPow(x,p);
    // return new RSA_KeySet(new RSA_PublicKey(p, g, h), new RSA_SecretKey(p, x));

    BigInteger p = getPrime(params.nb_bits, 1, params.prg);
    BigInteger q = getPrime(params.nb_bits, 1, params.prg);
    BigInteger n = p.multiply(q);
    BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    BigInteger e = BigInteger.valueOf(65537);
    //BigInteger d = e.modInverse(n);
    BigInteger d = extended_gcd(e, phi);
    while(d.compareTo(BigInteger.ZERO) < 0)
    {
      d = d.add(phi);
    }
    System.out.println("n " + n + " phi " + phi + " e " + e + " d " + d);
    return new RSA_KeySet(new RSA_PublicKey(n, e), new RSA_SecretKey(n, d));

  }

  public static BigInteger extended_gcd(BigInteger a, BigInteger b)
  {
    BigInteger x = BigInteger.ZERO;
    BigInteger y = BigInteger.ONE;
    BigInteger lastx = BigInteger.ONE;
    BigInteger lasty = BigInteger.ZERO; 

    while(b.compareTo(BigInteger.ZERO) != 0)
    {
      BigInteger q = a.divide(b);
      BigInteger c = a.mod(b);
      a = b;
      b = c;
      c = x;
      x = lastx.subtract(q.multiply(x));
      lastx = c;
      c = y;
      y = lasty.subtract(q.multiply(y));
      lasty = c;
    }
    return lastx;
  }


  public static BigInteger getPrime(int nb_bits, int certainty, Random prg)
  {
    //while(true)
    //{
      BigInteger p = new BigInteger(nb_bits, certainty, prg);
      if(p.signum() == -1)
      {
      //System.out.println(p);
        p = p.negate();
      }
      //BigInteger q = p.subtract(BigInteger.ONE);
      //System.out.println(q);
      //q = q.divide(new BigInteger("2"));
      //System.out.println(q);
      //if(q.isProbablePrime(certainty))
        return p;
    // } 
  }

  public static BigInteger order(BigInteger a, BigInteger n)
  {
    //System.out.println(a.intValue());
    for(BigInteger i = BigInteger.ONE; i.compareTo(n) < 0; i.add(BigInteger.ONE))
    {
      //System.out.println(i);
      if((a.modPow(i,n)).equals(BigInteger.ONE))
      {
        //System.out.println(i);
        return i;
      }
    }
    return BigInteger.ZERO;
  }

  public static void main(String [] args)
  {
//     Random generator = new Random();
//     BigInteger p = getPrime(Integer.parseInt(args[0]), 50, generator);
//     BigInteger p2 = p.subtract(BigInteger.ONE);
//     p2 = p2.divide(new BigInteger("2"));
//     System.out.println(p+" "+p2);
//     BigInteger g = new BigInteger(Integer.parseInt(args[0]), generator);
//     g = g.mod(p);
//     System.out.println(g + "  " + g.multiply(g) + "  " + g.pow(p2.intValue()).mod(p) + "  " + g.pow(p2.intValue()*2));
//     System.out.println(order(g, p));
// }
// }

  //UNCOMMENT ALL UNDER THIS LINE

  Random generator = new Random();
  RSA scheme = new RSA(Integer.parseInt(args[0]), generator);
  RSA_KeySet kset = scheme.KeyGen();
  System.out.println(kset.pkey.n);
  System.out.println(kset.pkey.e);
  RSA_PlainText plain = new RSA_PlainText(new BigInteger(Integer.parseInt(args[0]), generator).mod(kset.pkey.n));



  try
  {
    RSA_CipherText ctext = scheme.Encrypt(plain, kset.pkey);
    RSA_PlainText plain2 = scheme.Decrypt(ctext, kset.skey);
    System.out.println("plain1 " + plain.m);
    System.out.println("cipher1 " + ctext.c);
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
  