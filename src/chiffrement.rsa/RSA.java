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


class modular_pow
{
  public static BigInteger mod_pow(BigInteger m, BigInteger e, BigInteger n)
  {
    BigInteger b = m;
    //t = taille binaire de e
    String s = e.toString(2);
    System.out.println(s);
    int t = s.length();
    for(int i = t-2; i >= 0; i--)
    {
      b = b.multiply(b).mod(n);
      System.out.println(b);
      //Character.getNumericValue(element.charAt(2))
      if (Character.getNumericValue(s.charAt(i)) == 1)
      {
        b = b.multiply(m).mod(n);

      }
      System.out.println(b);
      System.out.println();
    }
    return b;
  }
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
      	BigInteger m = msg.c.modPow(skey.d, skey.n);
      	//BigInteger m = modular_pow.mod_pow(msg.c, skey.d, skey.n);
        return new RSA_PlainText(m);
      }
    }
  }

  public RSA_KeySet KeyGen()
  {

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
      BigInteger p = new BigInteger(nb_bits, certainty, prg);
      if(p.signum() == -1)
      {
        p = p.negate();
      }
        return p;
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

    long startTime = System.nanoTime();

    Random generator = new Random();
    RSA scheme = new RSA(Integer.parseInt(args[0]), generator);
    RSA_KeySet kset = scheme.KeyGen();
    long endTime = System.nanoTime();
    long duration = endTime - startTime;
    double seconds = (double)duration / 1000000000.0;
    System.out.println("time keygen " + seconds);
  // System.out.println(kset.pkey.n);
  // System.out.println(kset.pkey.e);
    startTime = System.nanoTime();
    RSA_PlainText plain = new RSA_PlainText(new BigInteger(Integer.parseInt(args[0]), generator).mod(kset.pkey.n));
    endTime = System.nanoTime();
    duration = endTime - startTime;
    seconds = (double)duration / 1000000000.0;
    System.out.println("time plain text " + seconds);

    try
    {
      startTime = System.nanoTime();
      RSA_CipherText ctext = scheme.Encrypt(plain, kset.pkey);
      endTime = System.nanoTime();
      duration = endTime - startTime;
      seconds = (double)duration / 1000000000.0;
      System.out.println("time encrypt text " + seconds);
      startTime = System.nanoTime();
      RSA_PlainText plain2 = scheme.Decrypt(ctext, kset.skey);
      endTime = System.nanoTime();
      duration = endTime - startTime;
      seconds = (double)duration / 1000000000.0;
      System.out.println("time encrypt text " + seconds);
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