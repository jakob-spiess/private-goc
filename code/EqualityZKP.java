import java.math.BigInteger;

public class EqualityZKP implements ZKP {

    public final BigInteger k1; // g1^r
    public final BigInteger k2; // g2^r
    public final BigInteger z;  // response

    private final CryptoGroup group;
    private final BigInteger g1;
    private final BigInteger g2;
    private final BigInteger a;
    private final BigInteger b;

    public EqualityZKP(
            CryptoGroup group,
            BigInteger g1,
            BigInteger g2,
            BigInteger a,
            BigInteger b,
            BigInteger k1,
            BigInteger k2,
            BigInteger z) {

        this.group = group;
        this.g1 = g1;
        this.g2 = g2;
        this.a = a;
        this.b = b;
        this.k1 = k1;
        this.k2 = k2;
        this.z = z;
    }

    @Override
    public boolean verify() {
        BigInteger c = FiatShamir.hashToZq(group.q, g1, g2, a, b, k1, k2);

        BigInteger lhs1 = group.pow(g1, z);
        BigInteger rhs1 = group.mul(k1, group.pow(a, c));

        BigInteger lhs2 = group.pow(g2, z);
        BigInteger rhs2 = group.mul(k2, group.pow(b, c));

        return lhs1.equals(rhs1) && lhs2.equals(rhs2);
    }
}
