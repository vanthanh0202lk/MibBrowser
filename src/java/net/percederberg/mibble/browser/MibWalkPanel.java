/*
 * Mibble MIB Parser (www.mibble.org)
 *
 * See LICENSE.txt for licensing information.
 *
 * Copyright (c) 2004-2017 Per Cederberg. All rights reserved.
 */

package net.percederberg.mibble.browser;

import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.util.HashMap;
import java.util.Map;

import javax.swing.*;

import net.percederberg.mibble.snmp.SnmpObjectType;

/**
 * The Mib Walk operations panel.
 *
 * @author Thanh
 * @version 1.00
 * @since 2.5
 */
public class MibWalkPanel extends JPanel {

    /**
     * The default component insets.
     */
    private static final Insets DEFAULT_INSETS = new Insets(2, 5, 2, 5);

    /**
     * The browser frame containing this panel.
     */
    private BrowserFrame frame;

    /**
     * The SNMP version to use.
     */
    private int version = 1;

    private MibTree mibTree = null;

    Map<String, String> listMibOid = new HashMap<String, String>();

    /**
     * The feedback flag. When this is set, the frame tree will be
     * updated with the results of the SNMP operations.
     */
    protected boolean feedback = true;

    /**
     * The blocked flag.
     */
    private boolean blocked = false;

    /**
     * The currently ongoing SNMP operation.
     */


    /**
     * The SNMP field panel.
     */
    private JPanel fieldPanel = new JPanel();

    /**
     * The host IP address label.
     */
    private JLabel AcctionWalkLabel = new JLabel("Acction");


    /**
     * The authentication type combo box.
     */
    private JComboBox<String> authTypeCombo = new JComboBox<>();


    /**
     * The privacy type combo box.
     */
    private JComboBox<String> privacyTypeCombo = new JComboBox<>();


    /**
     * The results text area.
     */
    private JTextArea resultsArea = new JTextArea();

    /**
     * The mibWalkArea text area.
     */
    private JTextArea mibWalkArea = new JTextArea();


    /**
     * The mibWalkArea text area.
     */
    private JTextArea sysLog = new JTextArea();


    /**
     * the Convert button.
     */
    private JButton convertButton = new JButton("Convert to Walk");

    /**
     * the Convert button.
     */
    private JButton loadFileButton = new JButton("Load File");


    /**
     * The clear button.
     */
    private JButton clearButton = new JButton("Clear");

    /**
     * the Write button.
     */
    private JButton WriteButton = new JButton("Write to text");


    /**
     *
     */
    BrowserFrame browserFrame;

    /**
     * Creates a new Mib Walk panel.
     *
     * @param frame the frame containing this panel
     */
    public MibWalkPanel(BrowserFrame frame) {
        super();
        this.frame = frame;
        initialize();
    }

    /**
     * Initializes the panel components.
     */
    private void initialize() {
        GridBagConstraints c;

        // Component initialization
        setLayout(new GridBagLayout());
        fieldPanel.setLayout(new GridBagLayout());
        authTypeCombo.addItem("None");
        authTypeCombo.addItem(SnmpAuthentication.MD5_TYPE);
        authTypeCombo.addItem(SnmpAuthentication.SHA1_TYPE);
        privacyTypeCombo.addItem("None");
        privacyTypeCombo.addItem(SnmpPrivacy.DES_TYPE);
        privacyTypeCombo.addItem(SnmpPrivacy.AES_TYPE);

        // Add results area
        mibWalkArea.setEditable(false);
        c = new GridBagConstraints();
        c.gridy = 2;
        c.weightx = 1.0d;
        c.weighty = 1.0d;
        c.fill = GridBagConstraints.BOTH;
        add(new JScrollPane(mibWalkArea), c);


        // Add SNMP fields
        initializeSnmpV1FieldPanel();
        c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        add(fieldPanel, c);

        // Add buttons
        c = new GridBagConstraints();
        c.gridy = 1;
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.NONE;
        add(initializeButtons(), c);

        // Add results area
        resultsArea.setEditable(false);
        c = new GridBagConstraints();
        c.gridy = 2;
        c.weightx = 1.0d;
        c.weighty = 1.0d;
        c.fill = GridBagConstraints.BOTH;
        add(new JScrollPane(resultsArea), c);


    }

    /**
     * Initializes the field panel for SNMP version 1.
     */
    private void initializeSnmpV1FieldPanel() {
        GridBagConstraints c;

        // Clear panel
        fieldPanel.removeAll();
        fieldPanel.invalidate();

        // Add AcctionWalkLabel
        c = new GridBagConstraints();
        c.gridy = 1;
        c.fill = GridBagConstraints.BOTH;
        c.insets = DEFAULT_INSETS;
        fieldPanel.add(AcctionWalkLabel, c);

        // Add separator
        c = new GridBagConstraints();
        c.gridy = 3;
        c.gridwidth = 4;
        c.weightx = 0.1d;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = DEFAULT_INSETS;
        fieldPanel.add(new JSeparator(), c);

    }


    /**
     * Creates and initializes the operation buttons.
     *
     * @return the panel containing the buttons
     */
    private JPanel initializeButtons() {
        JPanel panel = new JPanel();
        panel.setLayout(new FlowLayout());
        panel.add(loadFileButton);
        loadFileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                loadFile();
            }
        });

        panel.add(convertButton);
        convertButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                convertButton();
            }
        });

        panel.add(clearButton);
        clearButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                clearResults();
            }
        });

        panel.add(WriteButton);
        WriteButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                try {
                    WriteToTextFile();
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        });
        updateStatus();
        return panel;
    }

    /**
     * Performs a get next operation.
     */
    protected void convertButton() {
        clearResults();
        int cursor = 0;
        String linevalue = "";
        String preLineValue = "";
        String suffix = "";
        Boolean isTable = false;


        for (String line : mibWalkArea.getText().split("\\n")) {
            linevalue = line;
            preLineValue = "";
            suffix = "";
            try {
                preLineValue = line.substring(0, line.indexOf("="));
            } catch (IndexOutOfBoundsException ine) {
                appendResults("#Error preLineValue:" + linevalue + "\n");
                appendResults("#ErrorCode:" + ine.toString() + "\n");
            }
            try {
                suffix = line.substring(line.indexOf("="), line.length());
            } catch (IndexOutOfBoundsException ine) {
                appendResults("#Error suffixline:" + linevalue + "\n");
                appendResults("#ErrorCode:" + ine.toString() + "\n");
            }
            String oidName = null;
            String strIndex = "";
            String objectType = "";
            String data = "";
            Boolean isSubOidNotFound = false;

            if (preLineValue.contains("."))
                isTable = true;
            else
                isTable = false;
            try {
                cursor = 0;
                int strLen = line.length();
                String mibName = null;
                try {
                    mibName = line.substring(cursor, line.indexOf("::"));
                } catch (IndexOutOfBoundsException ine) {
                    appendResults("#Error mibName:" + line + "\n");
                    appendResults("#ErrorCode:" + ine.toString() + "\n");
                }
                cursor += mibName.length() + 2;
                if (isTable) {
                    try {
                        oidName = line.substring(cursor, line.indexOf("."));
                    } catch (IndexOutOfBoundsException ine) {
                        appendResults("#Error oidName:" + line + "\n");
                        appendResults("#ErrorCode:" + ine.toString() + "\n");
                    }
                    cursor += oidName.length()+1;
                    try {
                        strIndex = line.substring(cursor, line.indexOf("="));

                    } catch (IndexOutOfBoundsException ine) {
                        appendResults("#Error strIndex:" + line + "\n");
                        appendResults("#ErrorCode:" + ine.toString() + "\n");
                    }
                    cursor += strIndex.length() + 1;
                } else {
                    try {
                        oidName = line.substring(cursor, line.indexOf("="));
                    } catch (IndexOutOfBoundsException ine) {
                        appendResults("#Error oidName:" + line + "\n");
                        appendResults("#ErrorCode:" + ine.toString() + "\n");
                    }
                    cursor += oidName.length() + 1;
                }
                String oiId = listMibOid.get(oidName.trim());
                if (oiId == null)
                    oiId = "Not found Mib Name: " + mibName + " with oidName: " + oidName;
                try {
                    if (suffix.contains(":"))
                        objectType = line.substring(cursor, line.indexOf(": ")).trim();
                } catch (IndexOutOfBoundsException ine) {
                    appendResults("#Error objectType:" + line + "\n");
                    appendResults("#ErrorCode:" + ine.toString() + "\n");
                }
                cursor += objectType.length() + 2;

                if (objectType.equalsIgnoreCase("OID")) {
                    String subLine = null;
                    try {
                        subLine = line.substring(cursor, strLen);
                    } catch (IndexOutOfBoundsException ine) {
                        appendResults("#Error OID subLine:" + line + "\n");
                        appendResults("#ErrorCode:" + ine.toString() + "\n");
                    }
                    cursor = 0;
                    String mibName2 = null;
                    try {
                        mibName2 = subLine.substring(cursor, subLine.indexOf("::")).trim();
                    } catch (IndexOutOfBoundsException ine) {
                        appendResults("#Error OID mibName2:" + subLine + "\n");
                        appendResults("#ErrorCode:" + ine.toString() + "\n");
                    }
                    cursor += mibName2.length() + 3;
                    String oiName2 = null;
                    try {
                        oiName2 = subLine.substring(cursor, subLine.length());
                    } catch (IndexOutOfBoundsException ine) {
                        appendResults("#Error OID oiName2:" + subLine + "\n");
                        appendResults("#ErrorCode:" + ine.toString() + "\n");
                    }
                    String oiId2 = listMibOid.get(oiName2.trim());
                    if (oiId2 == null) {
                        oiId2 = "Not found sub Mib Name: " + mibName2 + " with oidName2: " + oiName2;
                        isSubOidNotFound = true;
                    }
                    data = oiId2;
                } else if (objectType.equalsIgnoreCase("Timeticks")) {
                    String subLine = null;
                    try {
                        subLine = line.substring(cursor, strLen);
                    } catch (IndexOutOfBoundsException ine) {
                        appendResults("#Error Timeticks subLine:" + subLine + "\n");
                        appendResults("#ErrorCode:" + ine.toString() + "\n");
                    }
                    String value = null;
                    try {
                        if (subLine.contains("(") && subLine.contains(")"))
                            value = subLine.substring(subLine.indexOf("(") + 1, subLine.indexOf(")"));
                        else
                            value = subLine;
                    } catch (IndexOutOfBoundsException ine) {
                        appendResults("#Error Timeticks value subLine:" + subLine + "\n");
                        appendResults("#ErrorCode:" + ine.toString() + "\n");
                    }
                    cursor += value.length() + 2;
                    data = value;
                } else if (objectType.equalsIgnoreCase("INTEGER")) {
                    String subLine = null;
                    try {
                        subLine = line.substring(cursor, strLen);
                    } catch (IndexOutOfBoundsException ine) {
                        appendResults("#Error INTEGER subLine:" + subLine + "\n");
                        appendResults("#ErrorCode:" + ine.toString() + "\n");
                    }
                    String value = null;
                    try {
                        if (subLine.contains("(") && subLine.contains(")"))
                            value = subLine.substring(subLine.indexOf("(") + 1, subLine.indexOf(")"));
                        else
                            value = subLine;
                    } catch (IndexOutOfBoundsException ine) {
                        appendResults("#Error INTEGER value:" + subLine + "\n");
                        appendResults("#ErrorCode:" + ine.toString() + "\n");
                    }
                    cursor += value.length() + 2;
                    data = value.replaceAll("[^\\d.]", "");
                    ;
                } else if (objectType.equalsIgnoreCase("Gauge32") ||
                        objectType.equalsIgnoreCase("Gauge64") ||
                        objectType.equalsIgnoreCase("Counter32") ||
                        objectType.equalsIgnoreCase("Counter64")) {
                    if (suffix.length() > 2) {
                        data = line.substring(cursor, strLen)
                                .replaceAll("[^\\d.]", "");
                        ;
                    } else
                        data = "";
                } else {
                    if (suffix.length() > 2)
                        data = line.substring(cursor, strLen);
                    else
                        data = "";
                }
                objectType = objectTypeParse(objectType.trim());
                String value = null;
                if (isTable) {
                    if (isSubOidNotFound)
                        value = "#" + oiId + "." + strIndex + " , " + objectType + " , " + data + "\n";
                    else {
                        strIndex = strIndex.replaceAll("ipv4","1");
                        strIndex = strIndex.replaceAll("ipv6","2");
                        strIndex = strIndex.replaceAll("('|\")", "");
                        String oidAndIndex = oiId + "." + strIndex ;

                        int loop = 0;
                        if(oidAndIndex.length() <31){
                            loop = 31 - oidAndIndex.length();
                            for (int i = 0 ; i < loop; i++){
                                oidAndIndex +=" ";
                            }
                        }
                        if(objectType.length() <13){
                            loop = 13 - objectType.length();
                            for (int i = 0 ; i < loop; i++){
                                objectType +=" ";
                            }
                        }
                        data = data.replaceAll("('|\")", "");
                        value =  oidAndIndex+", " + objectType + ", " + data + "\n";
                    }
                } else {
                    if (suffix.contains(":")) {//have data
                        int loop = 0;
                        if(oiId.length() <31){
                            loop = 31 - oiId.length();
                            for (int i = 0 ; i < loop; i++){
                                oiId +=" ";
                            }
                        }
                        if(objectType.length() <13){
                            loop = 13 - objectType.length();
                            for (int i = 0 ; i < loop; i++){
                                objectType +=" ";
                            }
                        }
                        data = data.replaceAll("('|\")", "");
                        value = oiId + ", " + objectType + ", " + data + "\n";
                    } else {
                        int loop = 0;
                        if(oiId.length() <31){
                            loop = 31 - oiId.length();
                            for (int i = 0 ; i < loop; i++){
                                oiId +=" ";
                            }
                        }
                        value = "#" + oiId + ", " + data + "\n";//have not data
                    }
                }
                if (value.contains("ipv4") || value.contains("ipv6") || value.contains("_snmpd") ||
                        value.contains("snmpd.conf")|| value.contains("Not found Mib Name") )
                    appendResults("#" + value);
                else
                    appendResults(value);
            } catch (Exception e) {
                appendResults("#Error:" + linevalue + "\n");
                appendResults("#ErrorCode:" + e.toString() + "\n");
            }
        }

    }

    protected void WriteToTextFile() throws IOException {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Specify a file to save");
        JFileChooser chooser = new JFileChooser();
        File targetFile = null;
        if (targetFile != null) {
            chooser.setSelectedFile(targetFile);
        } else {
            chooser.setSelectedFile(new File("sample_output.walk"));
        }
        int option = chooser.showSaveDialog(null);
        if (option == JFileChooser.APPROVE_OPTION) {
            targetFile = chooser.getSelectedFile();
        }

        FileWriter fileWriter = new FileWriter(targetFile);
        PrintWriter printWriter = new PrintWriter(fileWriter);
        for (String line : resultsArea.getText().split("\\n")) {
            printWriter.println(line);
        }
        printWriter.close();

    }


    public MibTreeNode getSelectedNode() {
        return (MibTreeNode) mibTree.getLastSelectedPathComponent();
    }


    /**
     * Load file
     */
    protected void loadFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
        String filePath = null;
        resetMibWalk();
        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            filePath = selectedFile.getAbsolutePath();
        }
        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader(filePath));
            String line = reader.readLine();
            while (line != null) {
                appendMibWalk(line + "\n");
                // read next line
                line = reader.readLine();
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Sets the SNMP version to use.
     *
     * @param version the new version number
     */
    public void setVersion(int version) {
        this.version = version;
        if (version == 1 || version == 2) {
            initializeSnmpV1FieldPanel();
        }
        validate();
    }

    /**
     * Sets the SNMP operation feedback flag. When this flag is set,
     * the result of the SNMP operation will update the MIB tree
     * selection.
     *
     * @param feedback the feedback flag
     */
    public void setFeedback(boolean feedback) {
        this.feedback = feedback;
    }

    /**
     * Blocks or unblocks GUI operations in this panel. This method
     * is used when performing long-running operations to inactivate
     * the user interface.
     *
     * @param blocked the blocked flag
     */
    public void setBlocked(boolean blocked) {
        this.blocked = blocked;
        updateStatus();
    }


    /**
     * Updates various panel components, such as text fields and
     * buttons. This method should be called when a new MIB node is
     * selected or when the UI has been blocked or unblocked.
     */
    public void updateStatus() {
        SnmpObjectType type = null;
        MibTreeNode node = frame.getSelectedNode();
        if (node != null) {
            type = node.getSnmpObjectType();
        }
    }

    /**
     * Clears the result area.
     */
    protected void clearResults() {
        synchronized (this) {
            resultsArea.setText("");
        }
    }

    /**
     * Appends a text to the results area.
     *
     * @param text the text to append
     */
    void appendResults(String text) {
        synchronized (this) {
            resultsArea.append(text);
            resultsArea.setCaretPosition(resultsArea.getText().length());
        }
    }

    /**
     * @param text
     */
    protected void appendMibWalk(String text) {
        synchronized (this) {
            mibWalkArea.append(text);
            mibWalkArea.setCaretPosition(mibWalkArea.getText().length());
        }
    }


    protected void resetMibWalk() {
        mibWalkArea.setText("");
    }

    protected String objectTypeParse(String str) {
        switch (str) {
            case "OID":
                return "ObjectID";
            case "STRING":
                return "OctetString";
            case "Hex-STRING":
                return "OctetString";
            case "Timeticks":
                return "TimeTicks";
            case "INTEGER":
                return "Integer";
            case "Gauge32":
                return "Gauge";
            case "Gauge64":
                return "Gauge64";
            case "Counter32":
                return "Counter";
            case "Counter64":
                return "Counter64";
            case "IpAddress":
                return "IpAddress";
            case "ipv4":
                    return "1";
            case "ipv6":
                return "2";
            default:
                return str;
        }

    }

    /**
     * @param mibTree
     */

    public void setMibTree(MibTree mibTree) {
        this.mibTree = mibTree;

    }

    public void setListMibOid(Map<String, String> listMibOidPr) {
        listMibOid.clear();
        int linno = 0;
        clearResults();
        for (Map.Entry<String, String> entry : listMibOidPr.entrySet()) {
            listMibOid.put(entry.getKey(), entry.getValue());
            linno++;
            appendResults("linno: " + linno + " " + entry.getKey() + " - " + entry.getValue() + "\n");
        }

    }


}
