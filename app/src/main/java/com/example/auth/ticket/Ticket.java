package com.example.auth.ticket;

import com.example.auth.app.ulctools.Commands;
import com.example.auth.app.ulctools.Utilities;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Date;

/**
 * TODO: Complete the implementation of this class. Most of the code are already implemented. You
 * will need to change the keys, design and implement functions to issue and validate tickets.
 */
public class Ticket {

    private static byte[] defaultAuthenticationKey = "BREAKMEIFYOUCAN!".getBytes();// 16-byte key
    public static int counter = 0;
    /** TODO: Change these according to your design. Diversify the keys. */
    private static byte[] authenticationKey = defaultAuthenticationKey;// 16-byte key
    private static byte[] hmacKey = "0123456789ABCDEF".getBytes(); // min 16-byte key

    public static byte[] data = new byte[192];

    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;



    private boolean isExpired = false;
    private Boolean isValid = false;
    private int remainingUses = 0;
    private int expiryTime = 0;

    private byte[] buid = null;
    private byte[] bcounter = null;
    private byte[] bextime = null;
    private byte[] bhmac = null;

    private static String infoToShow; //    Use this to show messages in Normal Mode

    private static int hmac_page_no = 8;
    private static int hmac_len = 1;
    private static int extime_page_no = 7;
    private static int extime_len = 1;
    private static int counter_page_no = 6;
    private static int counter_len = 1;
    private static int uid_page_no = 0;
    private static int uid_len = 2;


    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();


    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    /** Create a new ticket */
    public Ticket() throws GeneralSecurityException {
        // Set HMAC key for the ticket
        macAlgorithm = new TicketMac();
        macAlgorithm.setKey(hmacKey);

        ul = new Commands();
        utils = new Utilities(ul);
    }

    /** After validation, get ticket status: was it valid or not? */
    public boolean isValid() {
        return isValid;
    }

    /** After validation, get the number of remaining uses */
    public int getRemainingUses() {
        return remainingUses;
    }

    /** After validation, get the expiry time */
    public int getExpiryTime() {
        return expiryTime;
    }

    /** After validation/issuing, get information */
    public static String getInfoToShow() {
        String tmp = infoToShow;
        infoToShow = "";
        return tmp;
    }

    /**
     * Issue new tickets
     *
     * TODO: IMPLEMENT
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        boolean res;
        daysValid = 600;
        // Authenticate
        res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        // Example of writing:
        utils.eraseMemory();

        //write counter
        int counter = getMonoCounter(readCounter());

        if (counter % (uses+1) == 0){
//            infoToShow = "You are out of rides";
            remainingUses = uses;
        }else{
            for(int i = 0; i < ((uses + 1) - (counter % (uses + 1))); i++){
                writeIncrement();
            }
            remainingUses = uses;
        }

        // Update and write expiryTime
        validateCard();
        expiryTime = (int) (daysValid + (int)System.currentTimeMillis()/1000 % 65535);


        int expirydate = writeExpiryTime();
        System.out.print(expirydate);
        // Write new HMAC
//        writeHMAC();

        // Set information to show for the user
        infoToShow = "Reinitialized";

        return true;
    }


    private int getCurrentTime(){
        return (int)System.currentTimeMillis()/1000 % 65535;
    }

    private boolean validateCard(){


        isValid = validateExpiryDate() && (remainingUses < 0);

        return isValid;
    }

    public boolean use(int daysValid, int uses) throws GeneralSecurityException {
        boolean res;

        // Authenticate
        res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }
        this.readAll();

        isExpired = validateExpiryDate();
        if (isExpired) {
            Utilities.log("Card expired", true);
            infoToShow = "Card has expired";
            return false;
        }else {

            int counter = getMonoCounter(readCounter());

            if (counter % (uses+1) == uses){
                infoToShow = "You are out of rides";
                remainingUses = 0;
            }else {

                // Increment counter by 1
                writeIncrement();
                counter++;
                remainingUses = uses - counter % (uses + 1);

                int expiryDateInt = byteToInt(this.bextime);

                int timeDiff = expiryDateInt - getCurrentTime();

                writeHMAC();

                infoToShow = "Seconds left to use the card: " + String.valueOf(timeDiff) + "\n" + "Rides remaining: " + remainingUses;
            }
        }

        return true;
    }



    private int writeExpiryTime(){
        byte[] expiryTimeBuf = new byte[4]; // big-endian by default

        int buf_int = expiryTime;

        expiryTimeBuf = ByteBuffer.allocate(4).putInt(buf_int).array();

        utils.writePages(expiryTimeBuf, 0, extime_page_no, extime_len);
        return buf_int;

    }

    private void writeIncrement(){

        byte[] mcounter = new byte[4];

        mcounter[0] = (byte) 1;
        ul.writeBinary(41, mcounter, 0);
//        remainingUses-=1;

//        ByteBuffer wrapped = ByteBuffer.wrap(cnt); // big-endian by default
//        int cnt_int = wrapped.getInt();
//        cnt_int += by;
//
//        byte[] cnt_b = ByteBuffer.allocate(4).putInt(cnt_int).array();
//        System.out.println(bytesToHex(cnt_b));
//        utils.writePages(cnt_b, 0, counter_page_no, counter_len);
    }

    private byte[] readRemain(){
        byte[] cnt = new byte[4];
        utils.readPages(6, 1, cnt, 0);
        return cnt;
    }


    private int byteToInt(byte[] obj){
        ByteBuffer wrapped = ByteBuffer.wrap(obj); // big-endian by default
        int obj_int = wrapped.getInt();
        return obj_int;
    }

    private boolean validateExpiryDate(){

        int currentTime = (int)System.currentTimeMillis()/1000 % 65535;

        isExpired = currentTime >= expiryTime;

        return isExpired;
    }


    private int getMonoCounter(byte[] counterValue){
        return (counterValue[0] & 0xFF) << 0 | (counterValue[1] & 0xFF) << 8 | (counterValue[2] & 0xFF) << 16;
    }



    /**
     * Use ticket once
     *
     * TODO: IMPLEMENT
     */
    public boolean read() throws GeneralSecurityException {
        boolean res;

        // Authenticate
        res = true; // utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }
//        byte[] cnt_b = readRemain();
        this.readAll();
        String shmac = bytesToHex(this.bhmac);

        byte [] expiryDate = this.bextime;

        int expiryDateInt = byteToInt(expiryDate);

        int timeDiff = expiryDateInt - getCurrentTime();
        int counterCurent = getMonoCounter(readCounter());
        isExpired = validateExpiryDate();
        if (isExpired) {
            Utilities.log("Card expired", true);
            infoToShow = "Card has expired";
            return false;
        }else {
            infoToShow = "Seconds left to use the card: " + String.valueOf(timeDiff) + "\n" + "Rides remaining: " + remainingUses;
            }

        infoToShow = infoToShow + "\n" + "Current counter = " + counterCurent;
        return true;
    }

    /////////////////////HMAC PART/////////////////////////////////
    /*private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

    private static String toHexString(byte[] bytes) {
        Formatter formatter = new Formatter();
        for (byte b : bytes) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    public static String calculateRFC2104HMAC(String data, String key)
            throws SignatureException, NoSuchAlgorithmException, InvalidKeyException
    {
        SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);
        Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
        mac.init(signingKey);
        return toHexString(mac.doFinal(data.getBytes()));
    }*/

    private byte[] generateHMAC() {
        // Read the pages from the card
        byte[] integritiedData = new byte[4*(extime_len + counter_len + uid_len)];
        int db = 0;
        System.arraycopy(buid, 0, integritiedData, db, uid_len*4);
        Utilities.log(bytesToHex(buid), false);
        db += uid_len*4;
        System.arraycopy(bcounter, 0, integritiedData, db, counter_len*4);
        Utilities.log(bytesToHex(bcounter), false);
        db += counter_len*4;
        System.arraycopy(bextime, 0, integritiedData, db, extime_len*4);
        Utilities.log(bytesToHex(bextime), false);
        db += uid_len*4;
        // Generate HMAC
        try {
            byte[] hmac = macAlgorithm.generateMac(integritiedData);
            Utilities.log("HMACHMACHMACHMACHMACHMACHMACHMACHMACHMACHMAC", false);
            Utilities.log(bytesToHex(integritiedData), false);
            Utilities.log(bytesToHex(hmac), false);
            return hmac;
        }catch (java.security.GeneralSecurityException e){
            Utilities.log("security exception", true);
            return null;
        }
    }

    private void writeHMAC() {
        // Generate HMAC from the card data
        byte[] hmac = generateHMAC();

        // Write the HMAC to the card
        utils.writePages(hmac, 0, hmac_page_no, hmac_len);
    }

    private byte[] readHMAC() {
        byte[] hmac = new byte[hmac_len*4];
        utils.readPages(hmac_page_no, hmac_len, hmac, 0);
        return hmac;
    }

    private byte[] readTimeRem() {
//        return null;
        byte[] bextime = new byte[extime_len*4];
        utils.readPages(extime_page_no, extime_len, bextime, 0);
        return bextime;
    }

    private byte[] readUID() {
        byte[] buid = new byte[4*uid_len];
        utils.readPages(uid_page_no, uid_len, buid, 0);
        return buid;
    }

    private byte[] readCounter(){
        byte[] counterValue = new byte[4];
        utils.readPages(41, 1, counterValue, 0);
        return counterValue;
    }

    private void readAll(){
        Utilities.log("===================Readall=================", false);
        this.bcounter = this.readRemain();
        Utilities.log("counter", false);
        Utilities.log(bytesToHex(bcounter), false);
        this.buid = this.readUID();
        Utilities.log("uid", false);
        Utilities.log(bytesToHex(buid), false);
        this.bhmac = readHMAC();
        Utilities.log("hmac", false);
        Utilities.log(bytesToHex(bhmac), false);
        this.bextime = readTimeRem();
        Utilities.log("extime", false);
        Utilities.log(bytesToHex(bextime), false);
        Utilities.log("---------------------Readall---------------------", false);
    }
}