package Decrypt;

/**
* 
*    @(#)   MCCipherNgramDecrypt1
*/  
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Random;
import java.util.Scanner;

/**
*      MCCipherNgramDecrypt1
* 
* <br>
* 
* @author      jbsilva               
* @since       2013-07
*/
public final class MCCipherNgramDecrypt1 {
    private int plainSetSize = 26;
    private int cipherSetSize = 2;
    private int ngramPasses = 2;
    private int probSize = 2;
    private double tempEquiv = 0.001;
    private CipherUtilities cipherUtil;
    private ArrayList<Double> cipherProb;
    private ArrayList<Double> plainProb;
    private ArrayList<Integer> decryptKey;
    private ArrayList<Integer> cipherBounds;
    private ArrayList<ArrayList<Integer>> ascendingAlphSet;
    private ArrayList<ArrayList<Integer>> cipherPossSet;
    private ArrayList<Double> decryptProb;
    private ArrayList<Integer> testKey;
    private ArrayList<Integer> minDecryptKey;
    private ArrayList<Double> minDecryptProb;
    private ArrayList<Double> testProb;
    private ArrayList<String> topWords;
    private double energyEquiv;
    private double minEnergyEquiv = 100000000.0;
    private double secondOrderContrib = 1406.0;// 1206 makes max contribution 1
    private double topWordContrib = 0.5;// 1206 makes max contribution 1
    private Random Ran = new Random();
    private int alphabetSize = 26;
    private ArrayList<Character> cipherSet;
    private boolean showBars = false;
    private boolean decryptFromFile = false;
    
    /**
    *      MCCipherNgramDecrypt1 constructor
    *  
    */
    public MCCipherNgramDecrypt1(){
        cipherUtil = new CipherUtilities();
    }
    
    /**
    *         initialize performs all the initialization tasks necessary to
    *    run a simulation run.
    */
    public void initialize(){
        ascendingAlphSet = cipherUtil.getAscendAlphSet();
        cipherProb = cipherUtil.getCipherProb(); 
        plainProb = cipherUtil.getPlainProb(); 
        cipherSet = cipherUtil.getCipherCharSet();
        cipherPossSet = cipherUtil.getCipherPossSet();
        cipherBounds = cipherUtil.getCipherBoundsSet();
        if(cipherPossSet == null){
            cipherUtil.makeAllPossCipherPoss();
            cipherPossSet = cipherUtil.getCipherPossSet();
        }
    }
     
    /**
    *   makeInitKey generates a random starting decryption key 
    */
    public void makeInitKey(){
        cipherUtil.makeInitRandomKey();
        decryptKey = cipherUtil.getLastGenDecryptKey();
        decryptProb = cipherUtil.getLastGenDecryptProb();
        energyEquiv = cipherUtil.getLastGenDecryptEequiv();
    }
    
    
    /**
    *       runSimulation performs the main logic of the whole simulation by 
    *   calling on one simulation after it initializes it.
    */
    public void runSimulation(){
        makeInitKey();
        double lastEnergyEquiv = 0.0;
        double tempEquivInit = 50;
        int loweringTimeInit = 5000;
        int loweringTime = loweringTimeInit;
        int lowerN = 27;
        int lowerInd = -1;
        int maxT = lowerN*(loweringTime+500);
        int annealingCounter = 0;
        
        // output initial decryption
        String newText0 = cipherUtil.decryptUsingTestKey(decryptKey, cipherSet, getTestString());
        System.out.println("Decrypt | --------------------");
        System.out.println(newText0);
        System.out.println("--------------------------------");
        System.out.println("Energy Min : "+energyEquiv+"  initial");
                    
        // run many times
        for(int k = 0; k < 10000000; k++){
            // create initial decrypt key
            makeInitKey();
            
            // initialize counters for timing the change in temperatures
            lowerInd = 0;
            annealingCounter = 0;
            loweringTime = loweringTimeInit;
            
            // simulated annealing
            for(int u = 0; u < maxT; u++){
                // lower temperature when lowering time occurs
                if( annealingCounter % loweringTime == 0){
                    lowerInd++;
                    loweringTime += 500;
                    //System.out.println("Indice | "+lowerInd+"  lowerTime | "+ loweringTime+"   temp | "+tempEquiv);
                    annealingCounter = 0;
                }
                //calculate new temp
                tempEquiv = tempEquivInit*Math.pow(0.5, lowerInd);
                
                doOneStep();
                
                // if a new minimum value then show decryption
                if(lastEnergyEquiv != minEnergyEquiv){
                    String newText = cipherUtil.decryptUsingTestKey(minDecryptKey, cipherSet, getTestString());
                    System.out.println("Energy Min : "+minEnergyEquiv+"   after  "+k+ "  runs");
                    System.out.println("Decrypt | --------------------");
                    System.out.println(newText);
                    System.out.println("--------------------------------");
        
                    lastEnergyEquiv = minEnergyEquiv;
                }
                annealingCounter++;
                
                // if below this threshold than save to file
                if(minEnergyEquiv < 3.0){
                    cipherUtil.saveDecryptMinInfo(minDecryptKey,getTestString());
                }
            }
        }        
        
        cipherUtil.saveDecryptMinInfo(minDecryptKey,getTestString());
    }
    /**
    *   doOneStep does one step of the simulation 
    */
    public void doOneStep(){
        // initialize test move
        ArrayList<Integer> testKey = new ArrayList<Integer>(decryptKey);
        ArrayList<Double> testProb = new ArrayList<Double>();
        for(int u = 0; u  < plainSetSize;u++){
            testProb.add(0.0);
        }
        for(int u = 0; u  < cipherSetSize;u++){
            testProb.set(testKey.get(u), testProb.get(testKey.get(u))+cipherProb.get(u));
        }
        
        // choose cipher to test move
        int moveCipherChar = (int)(Ran.nextDouble()*cipherSetSize);
        int oldKey = testKey.get(moveCipherChar);
        double cipherCharProb = cipherProb.get(moveCipherChar);
        
        // make test move and calculate new probability distribution
        int newKey = cipherUtil.generateRandomPossCipherCharKey(moveCipherChar);
        testProb.set(oldKey, testProb.get(oldKey)-cipherCharProb);
        testProb.set(newKey, testProb.get(newKey)+cipherCharProb);
        
        // calculate new energy equivalent
        double newEnergy = cipherUtil.calcEnergyEquiv(testProb);
        double delE = newEnergy - energyEquiv;
        //System.out.println("Old Energy : "+energyEquiv+"     New Energy | "+newEnergy);
        
        // make a toss to avoid getting stuck in local minima
        if( (delE <= 0) || (Math.exp(-1.0*delE/tempEquiv) > Ran.nextDouble()) ){
            energyEquiv = newEnergy;
            decryptKey.set(moveCipherChar, newKey);
            decryptProb.set(oldKey, testProb.get(oldKey));
            decryptProb.set(newKey, testProb.get(newKey));    
        }
        
        // if this decryption key is new minima than save the key
        if(energyEquiv < minEnergyEquiv){
            minDecryptKey = new ArrayList<Integer>(decryptKey);
            minDecryptProb = new ArrayList<Double>(decryptProb);
            minEnergyEquiv = energyEquiv;
        }
    }
    
    public String getTestString(){
        return "zaioirsuza|uz|{i|cahduzhchcqiraic|k|kuh{iza|cpzaszubiicascp|";
    }    
    /**
    *       getCipherUtil returns the helper class which is used to load 
    *   measured probabilities
    * 
    * @return cipherUtilities class object
    */
    public CipherUtilities getCipherUtil(){
        return cipherUtil;
    }
    
    
    
    // test the class
    public static void main(String[] args) {
        MCCipherNgramDecrypt1 decrypt = new MCCipherNgramDecrypt1();
        
        // Amazon AWS dir
        //String dir = "/home/ubuntu/temp/";
        String dir = "./";
        decrypt.getCipherUtil().makeRestrictedPossSet(dir+"ascendingPlainOrderNumber.dat");
        decrypt.getCipherUtil().loadCipherProbData(dir+"Test2.dat",1); 
        decrypt.getCipherUtil().loadPlainProbData(dir+"procPlainProbAllMerge.dat");
        decrypt.getCipherUtil().loadCipherCharSet(dir+"Test2-mapAscii.txt");
        decrypt.initialize();
        //
        decrypt.runSimulation();
    }

}
