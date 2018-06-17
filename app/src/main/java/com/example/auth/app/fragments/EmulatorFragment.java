package com.example.auth.app.fragments;
/**
 * Developed for Aalto University course CS-E4300 Network Security.
 * Copyright (C) 2017 Aalto University
 */

import android.app.Fragment;
import android.media.AudioManager;
import android.media.ToneGenerator;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;

import com.example.auth.R;
import com.example.auth.app.ulctools.Reader;
import com.example.auth.app.ulctools.Utilities;
import com.example.auth.ticket.Ticket;

import java.security.GeneralSecurityException;
import java.util.Date;

public class EmulatorFragment extends Fragment {
    private static Ticket ticket;

    private static TextView ticket_info;

    private Button btn_issue;
    private Button btn_validate;
    private Button btn_write;
    public int issue_mode = 0;
    public boolean active = false;
    public boolean read_data_flag = false;
    public EmulatorFragment() {
        try {
            ticket = new Ticket();
            active = true;
        } catch (GeneralSecurityException g) {
            Utilities.log(g.toString(), true);
        }
    }

    private View.OnClickListener validate_listener = new View.OnClickListener() {
        public void onClick(View v) {
            btn_issue.setSelected(false);
            btn_validate.setSelected(true);
            btn_write.setSelected(false);
            issue_mode = 1;
        }
    };

    private View.OnClickListener read_data_listener = new View.OnClickListener(){
        public void onClick(View v) {
            btn_issue.setSelected(false);
            btn_validate.setSelected(false);
            btn_write.setSelected(true);
//            read_data_flag = true;
            issue_mode = 2;
        }

    };

    private View.OnClickListener issue_listener = new View.OnClickListener() {
        public void onClick(View v) {
            btn_issue.setSelected(true);
            btn_validate.setSelected(false);
            btn_write.setSelected(false);
            issue_mode = 0;
        }
    };

    public void setCardAvailable(boolean b) {
        btn_validate.setEnabled(b);
        btn_issue.setEnabled(b);
        active = b;
        switch (issue_mode){
            case 0: issue();
                break;
            case 1: read();
                break;
            case 2: write();
                break;

            }
        }
//        if (read_data_flag){
//            write();
//        }
//        else if issue_mode == 0 {
//            issue();
//        }else {
//            use();
//        }


    public void write() {
        if (active && Reader.connect()) {
            try {
                ticket.use(30, 10);
                ticket_info.setText(ticket.getInfoToShow());
            } catch (Exception e) {
                e.printStackTrace();
            }
            Reader.disconnect();
        }
    }


    public void issue() {
        if (active && Reader.connect()) {
            try {
                ticket.issue(30, 10);
                ticket_info.setText(ticket.getInfoToShow());
            } catch (Exception e) {
                e.printStackTrace();
            }
            Reader.disconnect();
        }
    }

    public void read() {
        if (active && Reader.connect()) {
            try {
                int currentTime = (int) ((new Date()).getTime() / 1000 / 60);
                int uses = ticket.getRemainingUses();
                int expiryTime = ticket.getExpiryTime();

                ticket.read();

                Reader.disconnect();
                boolean valid = ticket.isValid();
                String msg;

                if (valid) {
                    msg = "Used ticket successfully. The ticket was valid.";
                } else {
                    msg = "Ticket use FAILED. The following data may be INVALID.";
                }
                System.out.println(msg);
                Reader.history += "\n" + msg + "\n";

                String info = "\nCurrent time: "
                        + new Date((long) currentTime * 60 * 1000) + "\nExpiry time: "
                        + new Date((long) expiryTime * 60 * 1000) + "\nRemaining uses: " + uses;
                System.out.println(info);
                Reader.history += "\n" + info + "\n--------------------------------";

                if (valid) {
                    ToneGenerator toneG = new ToneGenerator(AudioManager.STREAM_RING, 100);
                    toneG.startTone(ToneGenerator.TONE_CDMA_ALERT_CALL_GUARD, 100);
                } else {
                    ToneGenerator toneG = new ToneGenerator(AudioManager.STREAM_RING, 100);
                    toneG.startTone(ToneGenerator.TONE_CDMA_ABBR_INTERCEPT, 100);
                }
                ticket_info.setText(ticket.getInfoToShow());
            } catch (GeneralSecurityException g) {
                Log.d("Error", g.toString());
            }
            Reader.disconnect();
        }
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }


    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        View v = inflater.inflate(R.layout.fragment_emulator, container, false);
        getActivity().getActionBar().setIcon(R.drawable.ic_launcher);

        ticket_info = (TextView) v.findViewById(R.id.ticket_info);
        ticket_info.setText("Ticket info");

        btn_issue = (Button) v.findViewById(R.id.issue_mode);
        btn_validate = (Button) v.findViewById(R.id.validate_mode);
        btn_write = (Button) v.findViewById(R.id.write_data);
        issue_mode = 1;
        btn_issue.setSelected(false);
        btn_validate.setSelected(true);
        btn_write.setSelected(false);

        btn_issue.setOnClickListener(issue_listener);
        btn_validate.setOnClickListener(validate_listener);
        btn_write.setOnClickListener(read_data_listener);
        return v;
    }

    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
    }
}
