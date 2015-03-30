/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package vistas;

import controladores.AES;
import controladores.Functions;
import javax.swing.JFrame;
import javax.swing.JOptionPane;

/**
 *
 * @author Julian
 */
public class FrameCifrar extends JFrame {

    JFrame parent;
    /**
     * Creates new form FrameCifrar
     */
    public FrameCifrar(JFrame parent) {
        this.parent = parent;
        initComponents();
        txtKey128.setEnabled(true);
        txtKey192.setEnabled(false);
        txtKey256.setEnabled(false);
        disableRounds();
        btnRound10.setVisible(false);
        btnRound11.setVisible(false);
        btnRound12.setVisible(false);
        btnRound13.setVisible(false);
        parent.setVisible(false);
        this.setLocationRelativeTo(null);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        buttonGroup1 = new javax.swing.ButtonGroup();
        jLabel1 = new javax.swing.JLabel();
        jSeparator1 = new javax.swing.JSeparator();
        txtPlainText = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        btnRoundInicial = new javax.swing.JButton();
        btnRound1 = new javax.swing.JButton();
        btnRound2 = new javax.swing.JButton();
        btnRound3 = new javax.swing.JButton();
        btnRound4 = new javax.swing.JButton();
        btnRound5 = new javax.swing.JButton();
        btnRound6 = new javax.swing.JButton();
        btnRound7 = new javax.swing.JButton();
        btnRound8 = new javax.swing.JButton();
        btnRound9 = new javax.swing.JButton();
        btnRound10 = new javax.swing.JButton();
        btnRound11 = new javax.swing.JButton();
        btnRound13 = new javax.swing.JButton();
        btnRoundFinal = new javax.swing.JButton();
        txtCipherText = new javax.swing.JTextField();
        jLabel3 = new javax.swing.JLabel();
        jButton15 = new javax.swing.JButton();
        jLabel4 = new javax.swing.JLabel();
        txtKey128 = new javax.swing.JFormattedTextField();
        jRadioButton1 = new javax.swing.JRadioButton();
        jRadioButton2 = new javax.swing.JRadioButton();
        jRadioButton3 = new javax.swing.JRadioButton();
        txtKey192 = new javax.swing.JFormattedTextField();
        txtKey256 = new javax.swing.JFormattedTextField();
        jSeparator2 = new javax.swing.JSeparator();
        btnRound12 = new javax.swing.JButton();
        btnAtras = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jLabel1.setIcon(new javax.swing.ImageIcon(getClass().getResource("/vistas/Cifrar.PNG"))); // NOI18N

        jSeparator1.setOrientation(javax.swing.SwingConstants.VERTICAL);

        jLabel2.setText("Mensaje: ");

        btnRoundInicial.setText("Round Inicial");
        btnRoundInicial.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRoundInicialActionPerformed(evt);
            }
        });

        btnRound1.setText("Round 1");
        btnRound1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRound1ActionPerformed(evt);
            }
        });

        btnRound2.setText("Round 2");
        btnRound2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRound2ActionPerformed(evt);
            }
        });

        btnRound3.setText("Round 3");
        btnRound3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRound3ActionPerformed(evt);
            }
        });

        btnRound4.setText("Round 4");
        btnRound4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRound4ActionPerformed(evt);
            }
        });

        btnRound5.setText("Round 5");
        btnRound5.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRound5ActionPerformed(evt);
            }
        });

        btnRound6.setText("Round 6");
        btnRound6.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRound6ActionPerformed(evt);
            }
        });

        btnRound7.setText("Round 7");
        btnRound7.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRound7ActionPerformed(evt);
            }
        });

        btnRound8.setText("Round 8");
        btnRound8.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRound8ActionPerformed(evt);
            }
        });

        btnRound9.setText("Round 9");
        btnRound9.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRound9ActionPerformed(evt);
            }
        });

        btnRound10.setText("Round 10");
        btnRound10.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRound10ActionPerformed(evt);
            }
        });

        btnRound11.setText("Round 11");
        btnRound11.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRound11ActionPerformed(evt);
            }
        });

        btnRound13.setText("Round 13");
        btnRound13.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRound13ActionPerformed(evt);
            }
        });

        btnRoundFinal.setText("Round Final");
        btnRoundFinal.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRoundFinalActionPerformed(evt);
            }
        });

        jLabel3.setText("Mensaje Cifrado:");

        jButton15.setText("Cifrar");
        jButton15.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton15ActionPerformed(evt);
            }
        });

        jLabel4.setText("Llave:");

        try {
            txtKey128.setFormatterFactory(new javax.swing.text.DefaultFormatterFactory(new javax.swing.text.MaskFormatter("HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH")));
        } catch (java.text.ParseException ex) {
            ex.printStackTrace();
        }
        txtKey128.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                txtKey128ActionPerformed(evt);
            }
        });

        buttonGroup1.add(jRadioButton1);
        jRadioButton1.setSelected(true);
        jRadioButton1.setText("128");
        jRadioButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jRadioButton1ActionPerformed(evt);
            }
        });

        buttonGroup1.add(jRadioButton2);
        jRadioButton2.setText("192");
        jRadioButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jRadioButton2ActionPerformed(evt);
            }
        });

        buttonGroup1.add(jRadioButton3);
        jRadioButton3.setText("256");
        jRadioButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jRadioButton3ActionPerformed(evt);
            }
        });

        try {
            txtKey192.setFormatterFactory(new javax.swing.text.DefaultFormatterFactory(new javax.swing.text.MaskFormatter("HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH")));
        } catch (java.text.ParseException ex) {
            ex.printStackTrace();
        }
        txtKey192.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                txtKey192ActionPerformed(evt);
            }
        });

        try {
            txtKey256.setFormatterFactory(new javax.swing.text.DefaultFormatterFactory(new javax.swing.text.MaskFormatter("HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH")));
        } catch (java.text.ParseException ex) {
            ex.printStackTrace();
        }
        txtKey256.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                txtKey256ActionPerformed(evt);
            }
        });

        btnRound12.setText("Round 12");
        btnRound12.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRound12ActionPerformed(evt);
            }
        });

        btnAtras.setText("Atras");
        btnAtras.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnAtrasActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(19, 19, 19)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jRadioButton3)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(txtKey256))
                            .addComponent(jButton15, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jRadioButton2)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(txtKey192))
                            .addComponent(jSeparator2, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel2)
                            .addComponent(jLabel4)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jRadioButton1)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(txtKey128))
                            .addComponent(txtPlainText, javax.swing.GroupLayout.PREFERRED_SIZE, 267, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jLabel1)
                        .addGap(26, 26, 26)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 14, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(btnAtras, javax.swing.GroupLayout.PREFERRED_SIZE, 258, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel3)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(32, 32, 32)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(btnRound1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(btnRound2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(btnRound3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(btnRound4, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(btnRound5, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(btnRound6, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(btnRound7, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(btnRound8, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(btnRound9, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(btnRound10, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(btnRound11, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(btnRound13, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(btnRoundFinal, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(btnRoundInicial, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 215, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(btnRound12, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                    .addComponent(txtCipherText, javax.swing.GroupLayout.PREFERRED_SIZE, 258, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(30, 30, 30))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(25, 25, 25)
                        .addComponent(jLabel2)
                        .addGap(3, 3, 3)
                        .addComponent(txtPlainText, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel4)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jRadioButton1)
                            .addComponent(txtKey128, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jRadioButton2)
                            .addComponent(txtKey192, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jRadioButton3)
                            .addComponent(txtKey256, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jButton15)
                        .addGap(18, 18, 18)
                        .addComponent(jSeparator2, javax.swing.GroupLayout.PREFERRED_SIZE, 11, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jLabel1))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(51, 51, 51)
                        .addComponent(btnRoundInicial)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnRound1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnRound2)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnRound3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnRound4)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnRound5)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnRound6)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnRound7)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnRound8)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnRound9)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnRound10)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnRound11)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnRound12)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnRound13)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnRoundFinal)
                        .addGap(34, 34, 34)
                        .addComponent(jLabel3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(txtCipherText, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(btnAtras)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addComponent(jSeparator1)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void btnRoundInicialActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRoundInicialActionPerformed
        DiagRounds dgr = new DiagRounds(this, "Round Inicial", 0);
        dgr.setVisible(true);
    }//GEN-LAST:event_btnRoundInicialActionPerformed

    private void btnRound1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRound1ActionPerformed
        DiagRounds dgr = new DiagRounds(this, "Round 1", 1);
        dgr.setVisible(true);
    }//GEN-LAST:event_btnRound1ActionPerformed

    private void btnRound2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRound2ActionPerformed
        DiagRounds dgr = new DiagRounds(this, "Round 2", 2);
        dgr.setVisible(true);
    }//GEN-LAST:event_btnRound2ActionPerformed

    private void btnRound3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRound3ActionPerformed
        DiagRounds dgr = new DiagRounds(this, "Round 3", 3);
        dgr.setVisible(true);
    }//GEN-LAST:event_btnRound3ActionPerformed

    private void btnRound4ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRound4ActionPerformed
        DiagRounds dgr = new DiagRounds(this, "Round 4", 4);
        dgr.setVisible(true);
    }//GEN-LAST:event_btnRound4ActionPerformed

    private void btnRound5ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRound5ActionPerformed
        DiagRounds dgr = new DiagRounds(this, "Round 5", 5);
        dgr.setVisible(true);
    }//GEN-LAST:event_btnRound5ActionPerformed

    private void btnRound6ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRound6ActionPerformed
        DiagRounds dgr = new DiagRounds(this, "Round 6", 6);
        dgr.setVisible(true);
    }//GEN-LAST:event_btnRound6ActionPerformed

    private void btnRound7ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRound7ActionPerformed
        DiagRounds dgr = new DiagRounds(this, "Round 7", 7);
        dgr.setVisible(true);
    }//GEN-LAST:event_btnRound7ActionPerformed

    private void btnRound8ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRound8ActionPerformed
        DiagRounds dgr = new DiagRounds(this, "Round 8", 8);
        dgr.setVisible(true);
    }//GEN-LAST:event_btnRound8ActionPerformed

    private void btnRound9ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRound9ActionPerformed
        DiagRounds dgr = new DiagRounds(this, "Round 9", 9);
        dgr.setVisible(true);
    }//GEN-LAST:event_btnRound9ActionPerformed

    private void btnRound10ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRound10ActionPerformed
        DiagRounds dgr = new DiagRounds(this, "Round 10", 10);
        dgr.setVisible(true);
    }//GEN-LAST:event_btnRound10ActionPerformed

    private void btnRound11ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRound11ActionPerformed
        DiagRounds dgr = new DiagRounds(this, "Round 11", 11);
        dgr.setVisible(true);
    }//GEN-LAST:event_btnRound11ActionPerformed
  
    private void btnRound13ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRound13ActionPerformed
        DiagRounds dgr = new DiagRounds(this, "Round 13", 13);
        dgr.setVisible(true);
    }//GEN-LAST:event_btnRound13ActionPerformed

    private void btnRoundFinalActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRoundFinalActionPerformed
        if(txtKey128.isEnabled()){
            DiagRounds dgr = new DiagRounds(this, "Round final", 10);
            dgr.setVisible(true);
        }else if(txtKey192.isEnabled()){
            DiagRounds dgr = new DiagRounds(this, "Round final", 12);
            dgr.setVisible(true);
        }else if(txtKey256.isEnabled()){
            DiagRounds dgr = new DiagRounds(this, "Round final", 14);
            dgr.setVisible(true);
        }        
    }//GEN-LAST:event_btnRoundFinalActionPerformed

    private void jButton15ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton15ActionPerformed
        //byte[] testBytes = Functions.hexStringToByteArray("414553206573206d757920666163696c");
        //byte[] testKey = Functions.hexStringToByteArray("2B7e151628aed2a6abf7158809cf4f3c");
        if(!txtPlainText.getText().equals("") && (!txtKey128.getText().equals("                                ") 
                || !txtKey192.getText().equals("                                              ") 
                || !txtKey256.getText().equals("                                                               "))){
            byte[] testBytes = Functions.hexStringToByteArray(txtPlainText.getText());
            byte[] testKey;
            if(txtKey128.isEnabled()){
                testKey = Functions.hexStringToByteArray(txtKey128.getText());
            }else if(txtKey192.isEnabled()){
                testKey = Functions.hexStringToByteArray(txtKey192.getText());
            }else{
                testKey = Functions.hexStringToByteArray(txtKey256.getText());
            }
            aes = new AES(testKey);	
            byte[] cipher = aes.encrypt(testBytes);
            txtCipherText.setText(Functions.bytesToHex(cipher));
            System.out.println("Cipher:  " + Functions.bytesToHex(cipher));
            System.out.println("Message: " + new String(aes.decrypt(cipher)));
            enableRounds();
        }else{
            JOptionPane.showMessageDialog(this, "Aún no has escrito un mensaje o una llave", "ERROR",JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_jButton15ActionPerformed

    private void txtKey128ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtKey128ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_txtKey128ActionPerformed

    private void jRadioButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jRadioButton3ActionPerformed
        txtKey128.setEnabled(false);
        txtKey192.setEnabled(false);
        txtKey256.setEnabled(true);
    }//GEN-LAST:event_jRadioButton3ActionPerformed

    private void jRadioButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jRadioButton1ActionPerformed
        txtKey128.setEnabled(true);
        txtKey192.setEnabled(false);
        txtKey256.setEnabled(false);
        btnRound10.setVisible(false);
        btnRound11.setVisible(false);
        btnRound12.setVisible(false);
        btnRound13.setVisible(false);
    }//GEN-LAST:event_jRadioButton1ActionPerformed

    private void txtKey192ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtKey192ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_txtKey192ActionPerformed

    private void txtKey256ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtKey256ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_txtKey256ActionPerformed

    private void jRadioButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jRadioButton2ActionPerformed
        txtKey128.setEnabled(false);
        txtKey192.setEnabled(true);
        txtKey256.setEnabled(false);
        btnRound12.setVisible(false);
        btnRound13.setVisible(false);
    }//GEN-LAST:event_jRadioButton2ActionPerformed

    private void btnRound12ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRound12ActionPerformed
        DiagRounds dgr = new DiagRounds(this, "Round 12", 12);
        dgr.setVisible(true);
    }//GEN-LAST:event_btnRound12ActionPerformed

    private void btnAtrasActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnAtrasActionPerformed
        parent.setVisible(true);
        this.dispose();
    }//GEN-LAST:event_btnAtrasActionPerformed

//    /**
//     * @param args the command line arguments
//     */
//    public static void main(String args[]) {
//        /* Set the Nimbus look and feel */
//        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
//        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
//         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
//         */
//        try {
//            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
//                if ("Nimbus".equals(info.getName())) {
//                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
//                    break;
//                }
//            }
//        } catch (ClassNotFoundException ex) {
//            java.util.logging.Logger.getLogger(FrameCifrar.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
//        } catch (InstantiationException ex) {
//            java.util.logging.Logger.getLogger(FrameCifrar.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
//        } catch (IllegalAccessException ex) {
//            java.util.logging.Logger.getLogger(FrameCifrar.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
//        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
//            java.util.logging.Logger.getLogger(FrameCifrar.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
//        }
//        //</editor-fold>
//
//        /* Create and display the form */
//        java.awt.EventQueue.invokeLater(new Runnable() {
//            public void run() {
//                new FrameCifrar().setVisible(true);
//            }
//        });
//    }
    public void disableRounds(){
        btnRoundInicial.setEnabled(false);
        btnRound1.setEnabled(false);
        btnRound2.setEnabled(false);
        btnRound3.setEnabled(false);
        btnRound4.setEnabled(false);
        btnRound5.setEnabled(false);
        btnRound6.setEnabled(false);
        btnRound7.setEnabled(false);
        btnRound8.setEnabled(false);
        btnRound9.setEnabled(false);
        btnRound10.setEnabled(false);
        btnRound11.setEnabled(false);
        btnRound12.setEnabled(false);
        btnRound13.setEnabled(false);
        btnRoundFinal.setEnabled(false);
    }
    public void enableRounds(){
        btnRoundInicial.setEnabled(true);
        btnRound1.setEnabled(true);
        btnRound2.setEnabled(true);
        btnRound3.setEnabled(true);
        btnRound4.setEnabled(true);
        btnRound5.setEnabled(true);
        btnRound6.setEnabled(true);
        btnRound7.setEnabled(true);
        btnRound8.setEnabled(true);
        btnRound9.setEnabled(true);
        btnRound10.setEnabled(true);
        btnRound11.setEnabled(true);
        btnRound12.setEnabled(true);
        btnRound13.setEnabled(true);
        btnRoundFinal.setEnabled(true);
    }
    AES aes;
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnAtras;
    private javax.swing.JButton btnRound1;
    private javax.swing.JButton btnRound10;
    private javax.swing.JButton btnRound11;
    private javax.swing.JButton btnRound12;
    private javax.swing.JButton btnRound13;
    private javax.swing.JButton btnRound2;
    private javax.swing.JButton btnRound3;
    private javax.swing.JButton btnRound4;
    private javax.swing.JButton btnRound5;
    private javax.swing.JButton btnRound6;
    private javax.swing.JButton btnRound7;
    private javax.swing.JButton btnRound8;
    private javax.swing.JButton btnRound9;
    private javax.swing.JButton btnRoundFinal;
    private javax.swing.JButton btnRoundInicial;
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.JButton jButton15;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JRadioButton jRadioButton1;
    private javax.swing.JRadioButton jRadioButton2;
    private javax.swing.JRadioButton jRadioButton3;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JSeparator jSeparator2;
    private javax.swing.JTextField txtCipherText;
    private javax.swing.JFormattedTextField txtKey128;
    private javax.swing.JFormattedTextField txtKey192;
    private javax.swing.JFormattedTextField txtKey256;
    private javax.swing.JTextField txtPlainText;
    // End of variables declaration//GEN-END:variables
}
