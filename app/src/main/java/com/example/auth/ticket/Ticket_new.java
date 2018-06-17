package com.example.auth.ticket;

import com.example.auth.app.ulctools.Commands;
import com.example.auth.app.ulctools.Utilities;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.util.Date;

/**
 * TODO: Complete the implementation of this class. Most of the code are already implemented. You
 * will need to change the keys, design and implement functions to issue and validate tickets.
 */
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Formatter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;



public class Ticket_new {

    private static byte[] defaultAuthenticationKey = "BREAKMEIFYOUCAN!".getBytes();// 16-byte key

    /** TODO: Change these according to your design. Diversify the keys. */
    private byte[] authenticationKey = new byte[16];// 16-byte key
    private static byte[] hmacKey = "%6!Lar^H#wB@DRL7bgzCZ#34e$anjGWQfZVY@9z=".getBytes(); // min 16-byte key
    private static byte[] secret = "yVf#XJP6RM?zBWy8Fm5wD#WbzQE9JfzJrYFs$gYp".getBytes(); // secret to be hashed with UID for authKey
    private static byte[] appTag = "GRP7".getBytes(); // tag to recognize application

    public static byte[] data = new byte[192];

    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private Boolean isValid = false;
    private int remainingUses = 0;
    private int expiryTime = 0;
    private int counterValue = 0;

    private static int counterLimitPos = 12; // Position of Counter limit field in the card
    private static int expiryTimePos = 13; // Position of expirytime field in the card
    private static int hmacPos = 25; // HMAC starting page
    private static int hmacLen = 4; // Length in pages (16 bytes)
    private static int appTagPos = 4; // Position of the application tag
    private static int maxRides = 30; // Maximum number of rides allowed on the card

    private static String infoToShow; // Use this to show messages in Normal Mode

    /** Create a new ticket */
    public Ticket_new() throws GeneralSecurityException {
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
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        boolean res;

        // Set the authenticationKey and try it
        setAuthenticationKey();
        res = utils.authenticate(authenticationKey);
        if (!res) {
            // Try the default key
            res = utils.authenticate(defaultAuthenticationKey);
            if (res) {
                // Format the card
                return format();
            } else {
                Utilities.log("Authentication failed in issue()", true);
                infoToShow = "Authentication failed";
                return false;
            }
        }

        // Validate card (initializes values if valid)
        validateCard();
        if (!isValid()) {
            Utilities.log("Card validation failed in issue()", true);
            return false;
        }

        // get current time
        int currentTime = (int) ((new Date()).getTime() / 1000 / 60);
        // Check that the card hasn't expired, if expired then set remainingUses to 0
        if (currentTime > expiryTime && expiryTime > 65535) {
            remainingUses = 0;
        }

        // Update remainingUses and write new counter limit
        remainingUses += uses;

        if (remainingUses > maxRides) {
            remainingUses -= uses;
            Utilities.log("Maximum 30 rides allowed on ticket", true);
            infoToShow = "Unable to increase rides past 30!\nRemaining uses: "+remainingUses;
            return false;
        }

        writeCounterLimit();

        // Update and write expiryTime
        expiryTime = daysValid;
        writeExpiryTime();

        // Write new HMAC
        writeHMAC();

        infoToShow = "Remaining Uses: "+remainingUses;

        return true;
    }

    /**
     * Use ticket once
     */
    public boolean use() throws GeneralSecurityException {
        boolean res;
        boolean firstUse = false;

        // Set the authenticationKey and try it
        setAuthenticationKey();
        res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in use()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        // Validate card
        validateCard();
        if (!isValid()) {
            Utilities.log("Card validation failed in use()", true);
            return false;
        }

        // Check what time is it
        int currentTime = (int) ((new Date()).getTime() / 1000 / 60);

        // Validate data
        validateData(currentTime);
        if (!isValid()) {
            Utilities.log("Data validation failed in use()", true);
            return false;
        }

        // Check if this is the first use
        if (expiryTime <= 65535) {
            firstUse = true;
            expiryTime = currentTime+expiryTime*24*60;
            writeExpiryTime();
        }

        // Increment counter by 1
        byte[] tempByte = new byte[4];
        tempByte[0] = (byte) 1;
        ul.writeBinary(41, tempByte, 0);
        remainingUses-=1;

        // If first use, rewrite hmac
        if (firstUse) {
            writeHMAC();
        }

        infoToShow = "Validation was a success\nRemaining Uses: "+remainingUses;

        return true;
    }

    /**
     * Format the card
     */
    public boolean format() {
        boolean status;

        // Reset the card memory
        status = utils.eraseMemory();
        if (!status) {
            infoToShow = "Card format failed!";
            return false;
        }

        // Change the key
        utils.writePages(authenticationKey, 0, 44, 4);

        // Write the application tag
        ul.writeBinary(appTagPos, appTag, 0);

        // Write the counter limit to the same as the counter value (remaining uses 0)
        setRemainingUses();
        remainingUses=0;
        writeCounterLimit();

        // Write the HMAC
        writeHMAC();

        // Set Auth0 and Auth1 to require authentication for write+write from pages 3-47
        byte[] Auth0 = new byte[4];
        Auth0[0] = (byte) 3; // Sets the protection to start from page 3
        byte[] Auth1 = new byte[4];
        Auth1[0] = (byte) 0; // Sets the protection to be for write+write
        ul.writeBinary(43, Auth1, 0);
        ul.writeBinary(42, Auth0, 0);

        infoToShow = "Card formatted!";

        return true;
    }

    /**
     * This function sets an unique authentication key for ticket.
     * Uses authenticationKey and UID hashed with SHA-256 and truncated to 128bits.
     */
    private void setAuthenticationKey() {
        // Read card UID
        byte[] uid = new byte[8];
        utils.readPages(0, 2, uid, 0);

        // Concatenate secret and the UID to form an unique authenticationKey
        byte[] key = new byte[uid.length+secret.length];
        System.arraycopy(secret, 0, key, 0, secret.length);
        System.arraycopy(uid, 0, key, secret.length, uid.length);

        // Hash the key with SHA-256 and take 128bits for the authenticationKey (start from 5th byte)
        try {
            MessageDigest sha256MessageDigest = MessageDigest.getInstance("SHA-256");
            byte[] keyHash = sha256MessageDigest.digest(key);
            System.arraycopy(keyHash, 5, authenticationKey, 0, 16);
        } catch (NoSuchAlgorithmException e) {
            Utilities.log("NoSuchAlgorithmException: "+e, true);
            System.exit(0);
        }
    }

    /**
     * This function checks if the cards format is correct.
     */
    private boolean validateFormat() {
        // Read the whole card and check that there is data
        data = utils.readMemory();
        if (data == null)
            return false;

        // Validate application tag
        for (int iter = 0; iter < 4; iter++)
        {
            byte a = data[appTagPos*4+iter];
            if (data[appTagPos*4+iter] != appTag[iter])
                return false;
        }

        // Check that tables aren't locked
        if (data[2*4+2]!=0 || data[2*4+3]!=0 || data[40*4]!=0 || data[40*4+1]!=0)
            return false;

        return true;
    }

    /**
     * This function checks if the cards hmac is correct (no one has tampered the card).
     */
    private boolean validateHMAC() {
        isValid = true;
        // Generate HMAC from the card data
        byte[] hmac = generateHMAC();

        // Read the HMAC on the card
        byte[] hmacCurr = new byte[4*hmacLen];
        utils.readPages(hmacPos, hmacLen, hmacCurr, 0);

        // Compare current HMAC and the generated HMAC byte by byte
        for (int iter = 0; iter < hmacLen*4; iter++)
        {
            if (hmac[iter] != hmacCurr[iter]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Validate the card
     * validatesFormat and HMAC
     * In case valid, initialize params for this class
     */
    private void validateCard() {
        isValid = true;

        // Validate the card format
        if (!validateFormat())
        {
            infoToShow = "Card is not formatted correctly";
            isValid = false;
        }

        // Validate the HMAC
        if (!validateHMAC()) {
            infoToShow = "Card integrity has been breached";
            isValid = false;
        }

        // If valid initialize params
        if (isValid()) {
            setRemainingUses();
            setExpiryTime();
        }
    }

    /**
     * Validate that the card hasn't expired and it has remaining uses
     */
    private void validateData(int currentTime) {
        isValid = true;

        // Check that there is 1 or more uses left
        if (remainingUses < 1) {
            infoToShow = "Validation failed.\nRemaining Uses: 0";
            isValid = false;
        }

        // Check that the card hasn't expired, if first use skip as well
        if (currentTime > expiryTime && expiryTime > 65535) {
            infoToShow = "Validation failed.\nCard has expired.";
            isValid = false;
        }
    }

    /**
     * Read the current remainingUses field from the card and set the variable
     */
    private void setRemainingUses() {
        // Read remainingUses field
        byte[] counterLimitBytes = new byte[4];
        utils.readPages(counterLimitPos, 1, counterLimitBytes, 0);

        // Read counter field
        byte[] couterValueBytes = new byte[4];
        utils.readPages(41, 1, couterValueBytes, 0);

        // Convert bytes to int
        int counterLimit = 0;
        int tmpCounterValue = 0;
        for (int iter = 0; iter <= 2; iter++) {
            int shift = (2 - iter) * 8;
            counterLimit += (counterLimitBytes[2 - iter] & 0xFF) << shift;
            tmpCounterValue += (couterValueBytes[2 - iter] & 0xFF) << shift;
        }

        counterValue = tmpCounterValue;
        remainingUses = counterLimit - counterValue;
    }

    /**
     * Read the current expiryTime field from the card and set the variable
     */
    private void setExpiryTime() {
        // Read the expiryTime field
        byte[] expiryTimeBytes = new byte[4];
        utils.readPages(expiryTimePos, 1, expiryTimeBytes, 0);

        // Convert bytes to int
        int tmpExpiryTime = 0;
        for (int iter = 1; iter <= 4; iter++) {
            int shift = (4 - iter) * 8;
            tmpExpiryTime += (expiryTimeBytes[4 - iter] & 0xFF) << shift;
        }

        expiryTime = tmpExpiryTime;
    }

    /**
     * Write the HMAC to the card
     */
    private void writeHMAC() {
        // Generate HMAC from the card data
        byte[] hmac = generateHMAC();

        // Write the HMAC to the card
        utils.writePages(hmac, 0, hmacPos, hmacLen);
    }

    /**
     * Write new counter limit to the card
     */
    private void writeCounterLimit() {
        // Calculate new value for counter limit page
        int counterLimit = remainingUses + counterValue;

        // Convert int to bytes
        byte[] counterLimitBytes = new byte[4];
        counterLimitBytes[0] = (byte)((counterLimit) & 0xFF);
        counterLimitBytes[1] = (byte)((counterLimit>>8) & 0xFF);
        counterLimitBytes[2] = 0;
        counterLimitBytes[3] = 0;

        // Write the remainingUses to the card
        utils.writePages(counterLimitBytes, 0, counterLimitPos, 1);
    }

    /**
     * Write new ExpiryTime
     */
    private void writeExpiryTime() {
        // Check if this is the issuing of a ticket or first use
        byte[] expiryTimeBytes = new byte[4];
        if (expiryTime <= 65535) {
            expiryTimeBytes[0] = (byte)((expiryTime) & 0xFF);
            expiryTimeBytes[1] = (byte)((expiryTime>>8) & 0xFF);
            expiryTimeBytes[2] = 0;
            expiryTimeBytes[3] = 0;
        } else {
            expiryTimeBytes[0] = (byte)((expiryTime) & 0xFF);
            expiryTimeBytes[1] = (byte)((expiryTime>>8) & 0xFF);
            expiryTimeBytes[2] = (byte)((expiryTime>>16) & 0xFF);
            expiryTimeBytes[3] = (byte)((expiryTime>>24) & 0xFF);
        }

        // Write the expiryTime to the card
        utils.writePages(expiryTimeBytes, 0, expiryTimePos, 1);
    }

    /**
     * Compute HMAC from the card data
     * HMAC uses first 5 pages + Counter limit + ExpiryTime to form the HMAC
     */
    private byte[] generateHMAC() {
        // Read the pages from the card
        byte[] cardData = new byte[8*4];
        utils.readPages(0, 5, cardData, 0);
        utils.readPages(counterLimitPos, 2, cardData, 6);

        // Generate HMAC
        try {
            byte[] hmac = macAlgorithm.generateMac(cardData);
            return hmac;
        } catch (GeneralSecurityException e) {
            Utilities.log("GeneralSecurityException: "+e, true);
            System.exit(0);
        }

        return null;
    }


}
