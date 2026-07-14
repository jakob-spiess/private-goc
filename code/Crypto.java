import java.math.BigInteger;
import java.security.SecureRandom;

public class Crypto {

    private final CryptoGroup group;
    private final SecureRandom random = new SecureRandom();

    public Crypto(CryptoGroup group) {
        this.group = group;
    }

    public KeyPair keyGen() {
        BigInteger x = new BigInteger(group.q.bitLength(), random).mod(group.q);
        BigInteger h = group.pow(group.g, x);
        return new KeyPair(x, h);
    }

    // Additive (exponential) ElGamal
    public Ciphertext encrypt(BigInteger m, BigInteger publicKey) {
        BigInteger r = new BigInteger(group.q.bitLength(), random).mod(group.q);

        BigInteger c1 = group.pow(group.g, r);
        BigInteger c2 = group.mul(
            group.pow(group.g, m),
            group.pow(publicKey, r)
        );

        return new Ciphertext(c1, c2);
    }

    // Decrypts to g^m
    public BigInteger decryptToGroupElement(Ciphertext c, BigInteger secretKey) {
        BigInteger s = group.pow(c.c1, secretKey);
        return group.mul(c.c2, group.inverse(s));
    }

    // Brute-force discrete log (small messages only!)
    public BigInteger bruteForceLog(BigInteger gm, int maxMessage) {
        BigInteger current = BigInteger.ONE;

        for (int i = 0; i <= maxMessage; i++) {
            if (current.equals(gm)) {
                return BigInteger.valueOf(i);
            }
            current = group.mul(current, group.g);
        }
        throw new IllegalArgumentException("Discrete log not found");
    }

    public NonNegativeBalanceZKP proveNonNegative(Ciphertext balanceCipher) {
        return new NonNegativeBalanceZKP(balanceCipher);
    }

    public EqualityZKP proveEqualDiscreteLog(
            BigInteger x,
            BigInteger g1,
            BigInteger g2,
            BigInteger a,
            BigInteger b) {
        BigInteger w = new BigInteger(group.q.bitLength(), random).mod(group.q);

        BigInteger k1 = group.pow(g1, w);
        BigInteger k2 = group.pow(g2, w);

        BigInteger c = FiatShamir.hashToZq(group.q, g1, g2, a, b, k1, k2);
        BigInteger z = w.add(c.multiply(x)).mod(group.q);

        return new EqualityZKP(group, g1, g2, a, b, k1, k2, z);
    }
}
