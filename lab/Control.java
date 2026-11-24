import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.util.Base64;

class Control {
    public static void main(String[] args) throws Exception {
        String decoded = new String(Base64.getDecoder().decode("Y29udHJvbA=="), StandardCharsets.UTF_8);
        try (var db = DriverManager.getConnection("jdbc:h2:mem:control"); var st = db.createStatement()) {
            try (var row = st.executeQuery("SELECT 7")) {
                if (!row.next() || row.getInt(1) != 7 || row.next()) throw new AssertionError("fixed read");
            }
            try (var rows = st.executeQuery("SELECT 7 WHERE 8 > 3 AND 4 = 5")) {
                if (rows.next() || !decoded.equals("control")) throw new AssertionError("fixed controls");
            }
        }
        System.out.println("{\"decode\":\"control\",\"read\":7,\"false_predicate\":\"empty\"}");
    }
}
