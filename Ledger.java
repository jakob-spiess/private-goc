import java.math.BigInteger;

public class Ledger {

    private final Crypto crypto;
    private final Ciphertext[][] matrix;

    public Ledger(Crypto crypto, int size) {
        this.crypto = crypto;
        this.matrix = new Ciphertext[size][size];
    }

    public boolean submitTransaction(
            int sender,
            int receiver,
            Ciphertext amount,
            ZKP proof) {

        if (!proof.verify()) {
            return false;
        }

        matrix[sender][receiver] = amount;
        return true;
    }

    public Ciphertext getEntry(int i, int j) {
        return matrix[i][j];
    }
}
