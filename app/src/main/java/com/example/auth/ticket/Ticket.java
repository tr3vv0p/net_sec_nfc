package com.example.auth.ticket;

import com.example.auth.app.ulctools.Commands;
import com.example.auth.app.ulctools.Utilities;
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
        remainingUses = uses;

        // Update and write expiryTime
        validateCard();
        expiryTime = (int) (daysValid + (int)System.currentTimeMillis()/1000 % 65535);


        int expirydate = writeExpiryTime();
        System.out.print(expirydate);
        // Write new HMAC

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

            byte[] cnt_b = this.bcounter;
            int cnt = writeIncrement(cnt_b, 1);


//            byte[] cnt_b = readRemain();
//            int cnt = writeIncrement(cnt_b, 1);
            int expiryDateInt = byteToInt(this.bextime);

            remainingUses = uses - cnt;
            int timeDiff = expiryDateInt - getCurrentTime();

            writeHMAC();


            if (remainingUses > 0 ){
                infoToShow = "Seconds left to use the card: " + String.valueOf(timeDiff) + "\n" + "Rides remaining: " + remainingUses;
            } else{
                infoToShow = "You are out of rides";
                remainingUses = 0;
            }




        }


        // Example of writing:

//        counter = counter+1;
//        System.out.println("CURRENT COUNTER "+String.valueOf(counter));
//        byte[] counter_b = ByteBuffer.allocate(4).putInt(counter).array();
//        System.out.println(bytesToHex(counter_b));
//        utils.writePages(counter_b, 0, 6, 1);
//
//        // Set information to show for the user
//        ByteBuffer wrapped = ByteBuffer.wrap(counter_b); // big-endian by default
//        int cnt_int = wrapped.getInt();

//        infoToShow = "Wrote: " + String.valueOf(cnt);

        return true;
    }

    private int writeExpiryTime(){
        byte[] expiryTimeBuf = new byte[4]; // big-endian by default

        int buf_int = expiryTime;

        expiryTimeBuf = ByteBuffer.allocate(4).putInt(buf_int).array();

        utils.writePages(expiryTimeBuf, 0, extime_page_no, extime_len);
        return buf_int;

    }

    private int writeIncrement(byte[] cnt, int by){
        ByteBuffer wrapped = ByteBuffer.wrap(cnt); // big-endian by default
        int cnt_int = wrapped.getInt();
        cnt_int += by;

        byte[] cnt_b = ByteBuffer.allocate(4).putInt(cnt_int).array();
        System.out.println(bytesToHex(cnt_b));
        utils.writePages(cnt_b, 0, counter_page_no, counter_len);
        return cnt_int;
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


        byte [] expiryDate = this.bextime;

        int expiryDateInt = byteToInt(expiryDate);

        int timeDiff = expiryDateInt - getCurrentTime();

        isExpired = validateExpiryDate();
        if (isExpired) {
            Utilities.log("Card expired", true);
            infoToShow = "Card has expired";
            return false;
        }else {
            infoToShow = "Seconds left to use the card: " + String.valueOf(timeDiff) + "\n" + "Rides remaining: " + remainingUses;

            }


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
        byte[] integritiedData = new byte[4*(extime_len+counter_len+uid_len)];
        int db = 0;
        System.arraycopy(buid, 0, integritiedData, db, uid_len);
        db += uid_len;
        System.arraycopy(bcounter, 0, integritiedData, db, uid_len);
        db += uid_len;
        System.arraycopy(bextime, 0, integritiedData, db, extime_len);
        db += uid_len;
        // Generate HMAC
        try {
            byte[] hmac = macAlgorithm.generateMac(integritiedData);
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

    private void readAll(){
        this.bcounter = this.readRemain();
        this.buid = this.readUID();
        this.bhmac = readHMAC();
        this.bextime = readTimeRem();
    }
}