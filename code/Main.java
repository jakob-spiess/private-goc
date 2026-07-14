import java.math.BigInteger;

public class Main {

    public static void main(String[] args) {
        printSection("0) Setup");
        /*
         * RFC 3526 group 14 prime (2048-bit MODP), represented in hex.
         * We use the prime-order subgroup with q = (p - 1) / 2 and g = 4.
         */
        String pHex =
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
                "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
                "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
                "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
                "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
                "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
                "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

        BigInteger p = new BigInteger(pHex, 16);
        BigInteger q = p.subtract(BigInteger.ONE).divide(BigInteger.TWO);
        BigInteger g = BigInteger.valueOf(4);

        boolean pPrime = p.isProbablePrime(128);
        boolean qPrime = q.isProbablePrime(128);
        boolean gHasOrderQ = g.modPow(q, p).equals(BigInteger.ONE) && !g.mod(p).equals(BigInteger.ONE);
        boolean groupOk = pPrime && qPrime && gHasOrderQ;

        if (!pPrime) {
            throw new IllegalStateException("p must be prime");
        }
        if (!qPrime) {
            throw new IllegalStateException("q must be prime");
        }
        if (!gHasOrderQ) {
            throw new IllegalStateException("g must have order q");
        }

        CryptoGroup group = new CryptoGroup(p, q, g);
        Crypto crypto = new Crypto(group);

        printSection("1) Group Parameters");
        System.out.println("p (bits) = " + p.bitLength());
        System.out.println("q (bits) = " + q.bitLength());
        System.out.println("g = " + g);
        System.out.println("p prime? " + pPrime);
        System.out.println("q prime? " + qPrime);
        System.out.println("g^q mod p = " + g.modPow(q, p));
        printCheck("Group validation", groupOk);
        System.out.println();

        // Key generation
        KeyPair alice = crypto.keyGen();
        KeyPair bob = crypto.keyGen();

        printSection("2) Key Generation");
        System.out.println("Alice public key h_A = " + shortBig(alice.publicKey));
        System.out.println("Bob public key h_B = " + shortBig(bob.publicKey));
        System.out.println();

        // Existing ZKP test (same plaintext encrypted under two keys with same randomness r)
        printSection("3) Equality ZKP Test");
        BigInteger m = BigInteger.valueOf(3);
        BigInteger r = BigInteger.valueOf(4);

        BigInteger gToR = group.pow(g, r);
        BigInteger gToM = group.pow(g, m);
        BigInteger cAlice = group.mul(gToM, group.pow(alice.publicKey, r));
        BigInteger cBob = group.mul(gToM, group.pow(bob.publicKey, r));

        System.out.println("Matrix cell entry (g^r, g^m h_A^r, g^m h_B^r):");
        System.out.println("(" + shortBig(gToR) + ", " + shortBig(cAlice) + ", " + shortBig(cBob) + ")");
        System.out.println();

        BigInteger hRatio = group.mul(alice.publicKey, group.inverse(bob.publicKey));
        BigInteger a = gToR;
        BigInteger b = group.pow(hRatio, r);

        EqualityZKP proof = crypto.proveEqualDiscreteLog(r, g, hRatio, a, b);
        boolean valid = proof.verify();
        printCheck("ZKP verification", valid);
        System.out.println();

        // Brute-force recovery benchmark after decrypting to g^m
        printSection("4) Brute-Force Recovery Benchmark");
        System.out.println("Goal: recover m from decrypted group element g^m via brute-force discrete log.");
        int[] warmupBounds = {100, 1_000, 5_000, 10_000, 20_000, 50_000, 100_000};
        int bestBound = -1;
        boolean warmupAllOk = true;

        for (int bound : warmupBounds) {
            BigInteger testM = BigInteger.valueOf(bound - 1L);
            Ciphertext ct = crypto.encrypt(testM, alice.publicKey);
            BigInteger gm = crypto.decryptToGroupElement(ct, alice.secretKey);

            long start = System.nanoTime();
            BigInteger recovered = crypto.bruteForceLog(gm, bound);
            long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

            boolean ok = recovered.equals(testM);
            warmupAllOk = warmupAllOk && ok;
            if (ok) {
                bestBound = bound;
            }
            System.out.println(
                    "  warmup | maxMessage=" + bound +
                    " | expected=" + testM +
                    " | recovered=" + recovered +
                    " | timeMs=" + elapsedMs +
                    " | " + (ok ? "PASS" : "FAIL")
            );
        }
        printCheck("Warmup benchmark checks", warmupAllOk);
        System.out.println("Largest warmup successful bound: " + bestBound);
        System.out.println();

        // Extended benchmark until runtime cutoff is reached.
        long cutoffMs = 10_000L;
        int extendedBound = 200_000;
        int maxExtendedBound = 20_000_000;
        int bestBeforeCutoff = bestBound;
        long lastElapsedMs = -1L;
        boolean extendedAllOk = true;
        boolean crossedCutoff = false;

        while (extendedBound <= maxExtendedBound) {
            BigInteger testM = BigInteger.valueOf(extendedBound - 1L);
            Ciphertext ct = crypto.encrypt(testM, alice.publicKey);
            BigInteger gm = crypto.decryptToGroupElement(ct, alice.secretKey);

            long start = System.nanoTime();
            BigInteger recovered = crypto.bruteForceLog(gm, extendedBound);
            long elapsedMs = (System.nanoTime() - start) / 1_000_000L;
            lastElapsedMs = elapsedMs;

            boolean ok = recovered.equals(testM);
            extendedAllOk = extendedAllOk && ok;
            System.out.println(
                    "  extended | maxMessage=" + extendedBound +
                    " | expected=" + testM +
                    " | recovered=" + recovered +
                    " | timeMs=" + elapsedMs +
                    " | " + (ok ? "PASS" : "FAIL")
            );

            if (!ok) {
                break;
            }
            if (elapsedMs > cutoffMs) {
                crossedCutoff = true;
                break;
            }

            bestBeforeCutoff = extendedBound;
            extendedBound = extendedBound * 2;
        }

        printCheck("Extended benchmark checks", extendedAllOk);
        System.out.println("Cutoff time threshold (ms): " + cutoffMs);
        System.out.println("Largest tested bound below cutoff: " + bestBeforeCutoff);
        if (crossedCutoff) {
            System.out.println("First bound above cutoff: " + extendedBound + " (timeMs=" + lastElapsedMs + ")");
        } else {
            System.out.println("Cutoff not reached up to maxExtendedBound=" + maxExtendedBound);
        }
        System.out.println();

        // Homomorphic addition tests: Enc(m1) * Enc(m2) = Enc(m1 + m2)
        printSection("5) Homomorphic Addition Tests");
        System.out.println("Rule: Enc(m1) * Enc(m2) decrypts to g^(m1 + m2).");
        int[][] pairs = {
                {2, 3},
                {7, 11},
                {25, 40},
                {123, 456},
                {700, 800}
        };
        boolean homomorphicAllOk = true;

        for (int[] pair : pairs) {
            BigInteger m1 = BigInteger.valueOf(pair[0]);
            BigInteger m2 = BigInteger.valueOf(pair[1]);

            Ciphertext c1 = crypto.encrypt(m1, alice.publicKey);
            Ciphertext c2 = crypto.encrypt(m2, alice.publicKey);
            Ciphertext cSum = c1.multiply(c2, group);

            BigInteger gmSum = crypto.decryptToGroupElement(cSum, alice.secretKey);
            BigInteger expected = m1.add(m2);
            BigInteger recovered = crypto.bruteForceLog(gmSum, expected.intValue() + 10);
            boolean ok = recovered.equals(expected);
            homomorphicAllOk = homomorphicAllOk && ok;

            System.out.println(
                    "  m1=" + m1 +
                    ", m2=" + m2 +
                    " | expectedSum=" + expected +
                    " | recoveredSum=" + recovered +
                    " | " + (ok ? "PASS" : "FAIL")
            );
        }
        printCheck("Homomorphic addition checks", homomorphicAllOk);

        boolean allOk = groupOk && valid && warmupAllOk && extendedAllOk && homomorphicAllOk;
        printSection("6) Final Summary");
        printCheck("Overall", allOk);
        System.out.println("Practical brute-force limit under " + cutoffMs + "ms: m <= " + bestBeforeCutoff);
        System.out.println();
        System.out.println("Done. Recompile and run Main to reproduce this full report.");
    }

    private static void printSection(String title) {
        System.out.println("============================================================");
        System.out.println(title);
        System.out.println("============================================================");
    }

    private static void printCheck(String label, boolean ok) {
        System.out.println("[" + (ok ? "PASS" : "FAIL") + "] " + label);
    }

    private static String shortBig(BigInteger value) {
        String s = value.toString();
        if (s.length() <= 42) {
            return s;
        }
        return s.substring(0, 18) + "..." + s.substring(s.length() - 18) + " (digits=" + s.length() + ")";
    }
}
