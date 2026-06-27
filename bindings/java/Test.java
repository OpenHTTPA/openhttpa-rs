public class Test {
    public static void main(String[] args) {
        System.out.println("Testing Java bindings for OpenHTTPA");
        try {
            org.openhttpa.ConfidentialClient client = new org.openhttpa.ConfidentialClient("sgx");
            client.close();
            System.out.println("Successfully created and closed ConfidentialClient.");
        } catch (Exception e) {
            System.err.println("Failed: " + e.getMessage());
        }
    }
}
