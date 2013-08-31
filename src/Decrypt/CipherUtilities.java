package Decrypt;

/***
* 
*    @(#)   CipherUtilities
*/  
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Random;
import java.util.Scanner;


/***
*      CipherUtilities
* 
* <br>
* 
* @author      jbsilva                
* @since       2013-07
*/
public final class CipherUtilities {
    private int plainSetSize = 26;
    private int cipherSetSize = 2;
    private int ngramPasses = 2;
    private int probSize = 2;
    private ArrayList<Double> plainProb;
    private ArrayList<Double> cipherProb;
    private ArrayList<Integer> cipherPossRange;
    private ArrayList<Integer> cipherBounds;
    private ArrayList<Integer> decryptKey;
    private ArrayList<Double> decryptProb;
    private ArrayList<ArrayList<Integer>> ascendingAlphSet;
    private ArrayList<ArrayList<Integer>> cipherPossSet;
    private ArrayList<ArrayList<Integer>> alphPossCipher;
    private ArrayList<Character> cipherSet;
    private ArrayList<String> topWords;
    private double energyEquiv;
    private double minEnergyEquiv = 100000000.0;
    private double secondOrderContrib = 1406.0;// 1206 makes max contribution 1
    private double topWordContrib = 0.5;// 1206 makes max contribution 1
    private Random Ran = new Random();
    private int alphabetSize = 26;
    private boolean decryptFromFile = false;

    public CipherUtilities(){
        
    }
    /**
    *       getLastGenDecryptKey returns the last generated decryption key from
    *   using the makeInitRandomKey methods
    * 
    * @return decryption key
    */
    public ArrayList<Integer> getLastGenDecryptKey(){
        return decryptKey;
    }
    /**
    *       getLastGenDecryptKey returns the probability of the decrypted plain text
    * given the last generated key
    * 
    * @return decryption probability
    */
    public ArrayList<Double> getLastGenDecryptProb(){
        return decryptProb;
    }
    /**
    *       getLastGenDecryptEequiv returns the energy equivalent for the last generated
    *   key
    * 
    * @return decryption eequiv
    */
    public double getLastGenDecryptEequiv(){
        return energyEquiv;
    }
    
    /**
    *       generateRandomPossCipherCharKey generates a
    *   cipher char integer that is drawn from the set
    *   of possible ciphers for the input plain set char
    * 
    *   @param u - input plain set char
    */
    public int generateRandomPossCipherCharKey(int u){
        ArrayList<Integer> temp = cipherPossSet.get(u);
        return temp.get((int)(Ran.nextDouble()*temp.size()));
    }
    
    /**
    *       makeTopWords returns an array of top words
    * 
    * @return topwords array
    */
    public ArrayList<String> makeTopWords(){
        topWords = new ArrayList<String>();
        topWords.add("the");
        topWords.add("you");
        topWords.add("have");
        topWords.add("was");
        topWords.add("for");
        topWords.add("that");
        topWords.add("this");
        return topWords;
    }
    
    /**
    *     makeInitRandomKeyFromPoss makes a random decryption key
    *   generated from a list of possible alphabet characters defined
    *   after using the makeAlphPoss method
    * 
    */
    public void makeInitRandomKeyFromPoss(){
        ArrayList<Integer> key = new ArrayList<Integer>();
        ArrayList<Double> keyProb = new ArrayList<Double>();
        for(int u = 0; u  < calcProbSize(plainSetSize, ngramPasses);u++){
            keyProb.add(0.0);
            if(u < cipherSetSize){
                key.add(-1);
            }
        }
        ArrayList<Integer> alph;
        
        for(int u = 0; u  < cipherSetSize;u++){
            int loc=0;
            if(u < plainSetSize){
                alph = alphPossCipher.get(u);
                boolean emptyCiph = true;
                while(emptyCiph){
                    loc = alph.get((int)(Ran.nextDouble()*alph.size()));
                    if(key.get(loc) == (-1)){emptyCiph = false;}
                }
                key.set(loc, u);
            }else{              
                boolean cont = true;
                boolean cont2 = true;
                int empty = -1;
                while(cont){
                    empty++;
                    if(key.get(empty) == (-1)){cont = false;}
                }
                loc = empty;
                int t3 = 0;
                cont = true;
                ArrayList<Integer> poss;
                while(cont){
                    t3 = (int)(Ran.nextDouble()*alphabetSize);
                    poss = alphPossCipher.get(t3);
                    empty = -1;
                    while(cont2 && empty < (poss.size()-1)){
                        empty++;
                        if(poss.get(empty) == loc){cont2 = false;cont = false;}
                    }
                }
                key.set(loc, t3);
            }
        }
        decryptKey  = key;
        decryptProb  = keyProb;
        energyEquiv = calcEnergyEquiv(keyProb);
    }
        
    /**
    *     makeInitRandomKeyFromPoss makes a random decryption key
    *   generated by throwing random alphabet character for each cipher char
    * 
    */
    public void makeInitRandomKey(){
        ArrayList<Integer> key = new ArrayList<Integer>();
        ArrayList<Double> keyProb = new ArrayList<Double>();
        for(int u = 0; u  < calcProbSize(plainSetSize, ngramPasses);u++){
            keyProb.add(0.0);
        }
        ArrayList<Integer> alph = new ArrayList<Integer>();
        for(int u = 0; u  < plainSetSize;u++){
            alph.add(u);
        }
        for(int u = 0; u  < cipherSetSize;u++){
            int loc = generateRandomPossCipherCharKey(u);
            key.add(loc);
            keyProb.set(key.get(u), keyProb.get(key.get(u))+cipherProb.get(u));
        }
        if(!decryptFromFile){
            decryptKey  = key;
            decryptProb  = keyProb;
            energyEquiv = calcEnergyEquiv(keyProb);
        }
    }

    /**
    *     findAllWithAlpha returns all the cipher character positions which contain
    *   the given character integer in the given key.
    *
    *   @param keyVal - decryption key to check
    *   @param charAlph - alphabet character int to find
    *   @return array of cipher char with given char in key
    */
    public ArrayList<Integer> findAllWithAlpha(ArrayList<Integer> keyVal ,int charAlph){
        ArrayList<Integer> test = new ArrayList<Integer>();
        for(int u  = 0; u < keyVal.size();u++){
            if(keyVal.get(u) == charAlph){test.add(u);}
        }
        return test;
    }
    
    /**
    *     decryptUsingTestKey returns deciphered text using the input 
    *   decryption key and cipher character set.
    * 
    *   @param testKey - decryption key
    *   @param testChar - cipher character set
    *   @param text - text to decipher
    *   @return deciphered text
    */
    public String decryptUsingTestKey(ArrayList<Integer> testKey,ArrayList<Character> testChar, String text){
        String decoded = "";
        printKey(testKey);
        for(int  u = 0; u < text.length();u++){
            if( text.charAt(u) != '\n'){
                int cipherPos = getCipherCharPosition( testChar ,text.charAt(u));
                //System.out.println("text| "+text.charAt(u)+" cipherPos | "+cipherPos+"   key| "+testKey.get(cipherPos));
                int keyOut = testKey.get(cipherPos);
                decoded = decoded + getNewCharFromIndex(keyOut);
            }else{
                decoded = decoded+"\n";
            }
        }
        return decoded;
    }
    
    /**
    *     printKey prints the current decryption key.
    * 
    *   @param testKey - decryption key
    */
    public void printKey(ArrayList<Integer> key){
        System.out.print("Key | ");
        for(int u = 0; u < key.size();u++){
            System.out.print(" "+getNewCharFromIndex(key.get(u)));
        }
        System.out.println();
    }
    
    /**
    *     convertToCharSet.
    * 
    *   @param testChar - cipher character set
    *   @return deciphered text
    */
    public ArrayList<Character> convertToCharSet(ArrayList<Integer> charIn){
        ArrayList<Character> temp = new ArrayList<Character> ();
        for(int u = 0; u < charIn.size(); u++){
            char t = (char)((int)charIn.get(u));
            temp.add(new Character(t));
        }
        return temp;
    }
    
    /**
    *     getCipherCharPosition returns the position of the given character
    *   in the cipher character set if in the set otherwise -1.
    * 
    *   @param ciphSet - cipher character set
    *   @param charIn - character to search for
    *   @return position of character in character set else -1
    */
    private int getCipherCharPosition(ArrayList<Character> ciphSet, char charIn){
        int u = 0;
        boolean posNotFound = true;
        while(posNotFound && u < ciphSet.size()){
            //System.out.println("cipherAt "+u+"   char| "+ciphSet.get(u)+"    looking for | "+charIn);
            if( ciphSet.get(u) == charIn){posNotFound = false;}
            if(posNotFound){
                u++;
            }
        }
        if(u == ciphSet.size()){
            u = -1;
        }
        return u;
    }
    
    /**
    *       getNewCharIndexAlphaNum map characters to 0-26 lowercase and 26-52 
    *   uppercase and rest numerical
    * 
    *   @param input character
    *   @return mapped integer
    */
    public int getNewCharIndexForAlphaNum(char charIn){
        if( ((int)(charIn)) < 64){
            return ((int)(charIn)+4);
        }
        if( Character.isAlphabetic(charIn) ) {
            // lower case
            if( (int)(charIn) > 96){
                return (int)(charIn)-97;
            //uppercase
            }else{
                    return ((int)(charIn)-39);
            }
        }
        return 63;
    }    
    
    /**
    *       printCipherBoundSet prints the set of possible character for each 
    *   cipher character
    */
    public void printCipherBoundSet(){
        ArrayList<Integer> temp;
        for(int u = 0; u < cipherPossSet.size();u++){
            temp = cipherPossSet.get(u);
            System.out.print("Cipher char | "+ cipherSet.get(u) +" Index "+u+" possible | ");
            for(int k = 0; k < temp.size();k++){
                System.out.print(" "+getNewCharFromIndex(temp.get(k)));
            }
            System.out.println();           
        }
        
    }
    
    /**
    *       getNewCharFromIndex map back from characters to 
    *   0-26 lowercase and 26-52 uppercase and rest numerical
    * 
    *   @param mapped integer
    *   @return character from mapping
    */
    public char getNewCharFromIndex(int charIn){
        // numerical
        if( (charIn > (2*alphabetSize-1))){
            return (char)(charIn-4);
        // upper case alphabet
        }else if( charIn > (alphabetSize-1) ){
            return (char)(charIn+39);
        }else{
            return (char)(charIn+97);
        }
    }
    
    /**
    *       loadPlainProbData loads the plainset probability from given file
    *   and sets the corresponding variable in this class.
    * 
    *   @param fname - filename
    */ 
    public void loadPlainProbData(String fname){
        ArrayList<Double> plain = getDoubleDataFromFileSingleLine(fname);
        plainProb = plain;
    }
    /**
    *       loadCipherProbData loads the cipher set probability from given file
    *   and sets the corresponding variable in this class.
    * 
    *   @param fname - filename
    *   @param mult - copies of prob data to put in array
    */ 
    public void loadCipherProbData(String fname, int mult){
        ArrayList<Double> ciph = getDoubleDataFromFileSingleLine(fname);
        cipherProb = ciph;
    }
 
    /**
    *       makeTestEncryptKeyVal makes key where any 
    *   position gives the position between 0-AlphabetSize which represents that char
    * 
    *   @param keysize - amount of characters in cipher set
    */
    public ArrayList<Integer> makeTestEncryptKeyVal(int keysize){
        ArrayList<Integer> temp2 = new ArrayList<Integer>();
        ArrayList<Integer> test = new ArrayList<Integer>();
        // make sure key has whole alphabet
        for(int u = 0; u < alphabetSize; u++){
            temp2.add(u);
        }
        for(int u = 0; u < keysize; u++){
            if(temp2.size() > 0){
                int loc =(int)(Math.random()*temp2.size());
                test.add(temp2.get(loc));
                ArrayList<Integer> temp = new ArrayList<Integer>();
                for(int k = 0; k < temp2.size();k++){
                    if(k != loc){temp.add(temp2.get(k));}
                }
                temp2 = temp;
            }else{
                test.add((int)(Math.random()*alphabetSize));
            }
        }
        return test;
    } 
   
    /**
    *       makeTestEncryptKeyChar makes key where any position 
    *   gives the ascii number of that position
    * 
    *   @param keysize - amount of characters in cipher set 
    *   @param maxChar - max ascii value to draw characters from 
    *   @param minChar - min ascii value to draw characters from 
    */
    public ArrayList<Integer> makeTestEncryptKeyChar(int keysize, int maxChar, int minChar){
        ArrayList<Integer> test = new ArrayList<Integer>();
        int tempVal =0;
        boolean badValue = true;
        for(int u = 0; u < keysize; u++){
            badValue = true;
            while(badValue){
                badValue = false;
                tempVal = (int)( (Math.random()*(maxChar-minChar))+minChar);
                for(int k = 0; k < test.size();k++){
                    if(test.get(k) == tempVal){badValue = true;}
                }
            }
            test.add((int)(tempVal));
        }
        return test;
    }
   
    /**
    *       makeCipherPossRange makes an array that contains 
    *   the indices of the cipher possibilities for each character
    *   in the cipher set.
    *   
    */
    public void makeCipherPossRange(){
        int ind = 0;
        ArrayList<Integer> temp = new ArrayList<Integer>();
        for(int u = 0; u < cipherPossSet.size();u++){
            temp.add(ind);
            //System.out.println("Cipher Ind |"+u+"   size| "+cipherPossSet.get(u).size());
            for(int k = 0; k < (cipherPossSet.get(u)).size();k++){
                if(k == (cipherPossSet.get(u).size()-1)){temp.add(ind);}
                ind++;
            }
                       
        }
        cipherPossRange = temp;
    }
    
    /**
    *       encryptTextFileUsingTest encrypts a text file based on a test 
    *   encryption key.
    * 
    * 
    * @param dir - directory of input text file
    * @param name - name of text file
    */
    public void encryptTextFileUsingTest(String dir, String name){
        String fName = dir+name;
        String efName = dir+"Encrypt-"+name;
        String dfName = dir+"Decrypt-"+name;
        int start = 97;
        int charset = 28;
        ArrayList<Integer> keyVal = makeTestEncryptKeyVal(charset);
        ArrayList<Integer> keyChar = makeTestEncryptKeyChar(charset, start,(start+charset));
        ArrayList<Character> keyCharFull = convertToCharSet(keyChar);
        
        //read file first    
        try{
            PrintStream out = new PrintStream(new FileOutputStream(
                efName,true));
            PrintStream outd = new PrintStream(new FileOutputStream(
                dfName,true));
            Scanner scanner = new Scanner(new File(fName));
                while(scanner.hasNext()){
                    String nextLine = scanner.next();
                    String newText = encryptUsingTestAlphaKey(keyVal, keyChar, nextLine);
                    outd.print(decryptUsingTestKey(keyVal, keyCharFull, newText));
                    out.print(newText);
                }
                out.println();
                outd.println();
                out.close();
                outd.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        try{
            PrintStream out2 = new PrintStream(new FileOutputStream(
                (dir+"KEY-"+name),true));
                for(int u = 0; u < keyVal.size();u++){
                    out2.println(keyCharFull.get(u)+"  "+getNewCharFromIndex(keyVal.get(u)));
                }
                out2.println();
                out2.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }
    
    /**
    *       makeRestrictedPossSet makes the set used to restrict possible alphabet
    *   based on probability of cipher character. Input should be a set of 26 
    *   rows where the first element is the most probable plainset char.
    * 
    * @param fname - restricted possible filename
    */
    public ArrayList<ArrayList<Integer>> makeRestrictedPossSet(String fname){
        ArrayList<ArrayList<Integer>> ascendingAlph = new ArrayList<ArrayList<Integer>>();
        try{
            Scanner scanner = new Scanner(new File(fname));
            while(scanner.hasNextLine()){
                Scanner scanner2 = new Scanner(scanner.nextLine());
                ArrayList<Integer> temp = new ArrayList<Integer>();
                while(scanner2.hasNextInt()){
                    temp.add(scanner2.nextInt());
                }
                ascendingAlph.add(temp);
            }
        }catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        if(ascendingAlphSet == null){
            ascendingAlphSet = ascendingAlph;
        }
        return ascendingAlph;
    }
     
    /**
    *       makeAlphPossCiphers makes the set to restrict the possible
    *   alphabet characters for the cipher set.
    * 
    * @param fname - restricted possible filename
    */
    public void makeAlphPossCiphers(String fname){
        ArrayList<Integer> temp = new ArrayList<Integer>();
        try{
            Scanner scanner = new Scanner(new File(fname));
            while(scanner.hasNextInt()){
                temp.add(scanner.nextInt());
            }
        }catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        alphPossCipher = new ArrayList<ArrayList<Integer>>();
        for(int u  = 0; u < alphabetSize;u++){
            alphPossCipher.add(new ArrayList<Integer>());
        }
        ArrayList<Integer> temp2;
        for(int u = 0; u  < temp.size();u++){
            temp2 = ascendingAlphSet.get(temp.get(u));
            for(int k = 0; k < temp2.size();k++){
                alphPossCipher.get(temp2.get(k)).add(u);
            }
        }
    }   
    
    /**
    *       loadDecryptKeyFromFile loads a decrypt key from a file.
    * 
    * @param fname - filename 
    */
    public void loadDecryptKeyFromFile(String fname){
        ArrayList<Character> temp = getCharDataFromFileSingleLine(fname);
        System.out.println("Key Size |"+temp.size()+" for cipher size |" +cipherSetSize );
        decryptKey = new ArrayList<Integer>();
        for(int u = 0; u < cipherSetSize; u++){
            decryptKey.add(getNewCharIndexForAlphaNum(temp.get(u)));
        }
        decryptFromFile = true;
        ArrayList<Double> keyProb = new ArrayList<Double>();
        for(int u = 0; u  < calcProbSize(plainSetSize, ngramPasses);u++){
            keyProb.add(0.0);
        }
        ArrayList<Integer> alph = new ArrayList<Integer>();
        for(int u = 0; u  < plainSetSize;u++){
            alph.add(u);
        }
        for(int u = 0; u  < cipherSetSize;u++){
            keyProb.set(decryptKey.get(u), keyProb.get(decryptKey.get(u))+cipherProb.get(u));
        }
        decryptProb = keyProb;
        energyEquiv =calcEnergyEquiv(keyProb);
    }
    
    /**
    *       loadCipherCharSet loads the cipher character set from a file.
    * 
    * @param fname - filename 
    */
    public void loadCipherCharSet(String fname){
        cipherSet = getCharDataFromFileSingleLine(fname);       
        cipherSetSize = cipherSet.size();
    }
    
    
    /**
    *      getDoubleDataFromFile gets data from a data file consisting of a single
    *   line.
    * 
    * @param fname - file name
    */
    public ArrayList<Double> getDoubleDataFromFileSingleLine(String fname){
        ArrayList<Double> dat = new ArrayList<Double>();
        //read file first    
        try{
            Scanner scanner = new Scanner(new File(fname));
                while(scanner.hasNextDouble()){
                    dat.add(scanner.nextDouble());
                }
            }catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return dat;
    }
    
    /***
    *      getDoubleDataFromFile gets data from a data file consisting of a single
    *   line.
    * 
    * @param fname - file name
    */
    public ArrayList<Character> getCharDataFromFileSingleLine(String fname){
        ArrayList<Character> dat = new ArrayList<Character>();
        //read file first    
        try{
            Scanner scanner = new Scanner(new File(fname));
                while(scanner.hasNext()){
                    dat.add((scanner.nextLine().replaceAll("\\s","")).charAt(0));
                }
            }catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return dat;
    }
    
    /**
    *       calcProbSize calculates the size of a probability array containing 
    *   up to n order set ngram.
    * 
    * @param N - set size
    * @param npass - order of set
    */
    public int calcProbSize(int N, int npass){
        int sum;
        sum = (int)((1.0-Math.pow((double)N, npass+1))/(1.0-(double)N))-1;
        //System.out.println("Regular Sum | "+sum);
        return sum;
    } 
    
    /**
    *   makeAllPossCipherPoss makes a cipher possibilities based on no decryption restrictions
    */
    public void makeAllPossCipherPoss(){
        // initialize to all possible decryption if not bounded by any constraints
        if(cipherPossSet == null){
            cipherPossSet = new ArrayList<ArrayList<Integer>>();
            ArrayList<Integer> temp = new ArrayList<Integer>();
            for(int u = 0; u < plainSetSize; u++){
                temp.add(u);
            }
            for(int u = 0; u < cipherSetSize;u++ ){
                cipherPossSet.add(new ArrayList<Integer>(temp));
            }
        }
    }
    
    /**
    *       setCipherBounds sets the size of cipher char possibilities based 
    *   on the input file integer value and the set of ascending probability 
    *   plain set.
    * 
    * @param fname - filename
    */
    public void setCipherBounds(String fname){
        ArrayList<Integer> temp = new ArrayList<Integer>();
        try{
            Scanner scanner = new Scanner(new File(fname));
            while(scanner.hasNextInt()){
                temp.add(scanner.nextInt());
            }
        }catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        cipherBounds = temp;
        cipherPossSet = new ArrayList<ArrayList<Integer>>();
        
        for(int u = 0; u  < temp.size();u++){
            cipherPossSet.add(ascendingAlphSet.get(temp.get(u)));
        }
    }
    
    
    /**
    *       loadCipherPossOverride overrides the possible decryption 
    *   of ciphers given.
    * 
    * @param fname - filename
    */
    public void loadCipherPossOverride(String fname){
        try{
            Scanner scanner = new Scanner(new File(fname));
            while(scanner.hasNextLine()){
                Scanner scanner2 = new Scanner(scanner.nextLine());
                ArrayList<Integer> temp = new ArrayList<Integer>();
                int i = 0;int cipherChar = 0;
                while(scanner2.hasNextInt()){
                    if(i == 0){
                        cipherChar = scanner2.nextInt();
                    }else{
                        temp.add(scanner2.nextInt());
                    }
                    i++;
                }
                System.out.println("Char | "+cipherChar+"     temp |"+temp.size());
                cipherPossSet.set(cipherChar,temp);
            }
        }catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
    
    /**
    *       saveDecryptMinInfo saves the decrypt key info and the
    * decryption of the input text
    * 
    * @param minDecryptKey - input decrypt key
    * @param text - text to decrypt
    */
    public void saveDecryptMinInfo(ArrayList<Integer> minDecryptKey,String text){
        String efName = "decryptInfo.dat";
        //read file first    
        try{
            PrintStream out = new PrintStream(new FileOutputStream(
                efName,true));
                out.print("Decrypt Key | ");
                for(int u = 0; u < minDecryptKey.size(); u++){
                    out.print(" "+ getNewCharFromIndex(minDecryptKey.get(u)));
                }
                out.println();
                out.println();
                out.println();
                String newText = decryptUsingTestKey(minDecryptKey, cipherSet, text);
                out.print(newText);
                out.println();
                out.println();
                out.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }
    
    /**
    *       saveEquivEData save the double energy equivalent value
    *   in a file.
    * 
    * @param equiv - e equiv to save
    * @param newLine - start a new line if true
    */
    public void saveEquivEData(double equiv, boolean newLine){
        String efName = "eEquiv.dat";
        //read file first    
        try{
            PrintStream out = new PrintStream(new FileOutputStream(efName,true));
            if(newLine){
                out.println();
            }else{
                out.print(equiv+" ");
            }
            out.close();
        }catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }
    
    /**
    *       makeConsolidatedArrayListDbl consolidates the array of
    *   arrays into a single array
    * 
    * @param inArr - array of array to consolidate
    * @return consolidated array
    */
    public ArrayList<Double> makeConsolidatedArrayListDbl(ArrayList<ArrayList<Double>> inArr){
        ArrayList<Double> out = new ArrayList<Double>();
        for(int u = 0; u < inArr.size();u++){
        for(int k = 0; k < inArr.get(u).size();k++){
            out.add(inArr.get(u).get(k));
        }}
        return out;
    }
    
    /**
    *       makeConsolidatedArrayListDblFl consolidates the array of
    *   arrays into a single array
    * 
    * @param inArr - array of array to consolidate
    * @return consolidated array
    */
    public ArrayList<Float> makeConsolidatedArrayListDblFl(ArrayList<ArrayList<Double>> inArr){
        ArrayList<Float> out = new ArrayList<Float>();
        for(int u = 0; u < inArr.size();u++){
        for(int k = 0; k < inArr.get(u).size();k++){
            out.add((float)(inArr.get(u).get(k).floatValue()));
        }}
        return out;
    }

    /**
    *       makeConsolidatedArrayListFl consolidates the array of
    *   arrays into a single array
    * 
    * @param inArr - array of array to consolidate
    * @return consolidated array
    */
    public ArrayList<Float> makeConsolidatedArrayListFl(ArrayList<ArrayList<Float>> inArr){
        ArrayList<Float> out = new ArrayList<Float>();
        for(int u = 0; u < inArr.size();u++){
        for(int k = 0; k < inArr.get(u).size();k++){
            out.add((float)(inArr.get(u).get(k)));
        }}
        return out;
    }
    
    /**
    *       makeConsolidatedArrayListInt consolidates the array of
    *   arrays into a single array
    * 
    * @param inArr - array of array to consolidate
    * @return consolidated array
    */
    public ArrayList<Integer> makeConsolidatedArrayListInt(ArrayList<ArrayList<Integer>> inArr){
        ArrayList<Integer> out = new ArrayList<Integer>();
        for(int u = 0; u < inArr.size();u++){
        for(int k = 0; k < inArr.get(u).size();k++){
            out.add(inArr.get(u).get(k));
        }}
        return out;
    }   

    /**
    *       encryptUsingTestAlphaKey encrypts text using the input
    *   encryption key.
    * 
    * @param keyVal - input encryption key 
    * @param charVal - input encryption key characters
    * @param text - text to encrypt
    * @return encrypted text
    */
    public String encryptUsingTestAlphaKey(ArrayList<Integer> keyVal, ArrayList<Integer> charVal , String text){
        String newText = "";
        for(int u  = 0 ; u < keyVal.size();u++){
        //        System.out.println("Char at | "+u+" is now char |" +keyVal.get(u));
        }
        for(int u = 0; u < text.length();u++){
            if(Character.isAlphabetic(text.charAt(u))){
                char val = Character.toLowerCase(text.charAt(u));
                ArrayList<Integer> cryptPoss = findAllWithAlpha(keyVal,getNewCharIndexForAlphaNum(val));
                int ciphVal = cryptPoss.get((int)(Math.random()*cryptPoss.size()));
                int newCharAscii = charVal.get(ciphVal );
                //System.out.println("Ascii CHar |" +String.valueOf(Character.toChars(newCharAscii)));
                newText = newText.concat(String.valueOf(Character.toChars(newCharAscii)));
            }else if(text.charAt(u) == '\n'){
                newText.concat("\n");
            }
        }
        return newText;
    }
    
    /**
    *       calcEnergyEquiv calculates an energy equivalent based on decrypted
    *   probabilities being compared with measured plain alphabet probabilities
    * 
    * @param keyProb - decrypt key
    * @return energy equiv 
    */
    public double calcEnergyEquiv(ArrayList<Double> keyProb ){
        double e = 0.0;
        for(int u = 0; u < plainSetSize;u++){
        //    System.out.println("Plain Prob | "+plainProb.get(2*u)+"    keyProb |" + keyProb.get(u) );
            e += Math.abs((plainProb.get(2*u)-keyProb.get(u))/plainProb.get(2*u));
        }        
        return e;
    }
    
    /**
    *       makeCompatibleRandomSwap makes a compatible swap based on the 
    *   both swap characters having common possible alphabet decryptions.
    * 
    * @param temp - decrypt key
    * @param location - the cipher char int position
    * @param locKey - the cipher char decrypt key
    * @return 
    */
    public int makeCompatibleRandomSwap(ArrayList<Integer> temp, int location, int locKey){
        boolean badSwap = true;
        int swap = 0;
        ArrayList<Integer> temp2;
        while(badSwap){
            temp2 = alphPossCipher.get(locKey);
            swap =  (int)(Ran.nextDouble()*temp2.size());
            if(temp2.get(swap) != location){badSwap = false;}
        }
        return swap;
    }
    
    /**
    *       calculates the energy contribution based on the decrypted
    *   text containing top words.
    *   
    * 
    * @param temp - decryptKey
    * @param text - encrypted text
    * @return energy equiv contribution
    */
    public double calcWordBonus(ArrayList<Integer> temp, String text){
        double e = 0.0;
        String newText = decryptUsingTestKey(decryptKey, cipherSet, text);
        for(int u = 0; u < topWords.size();u++){
            if(newText.contains(topWords.get(u))){e -= topWordContrib;}
        }
        return e;
    }
    
    /**
    *       getCipher2Index returns the integer position of the 
    *   second cipher character position for the 2-gram probability.
    * 
    * @param i - 2-gram index
    * @return cipher integer index
    */
    public int getCipher2Index(int i){
        return i % cipherSetSize;
    }
    
    /**
    *       getCipher1Index returns the integer position of the 
    *   first cipher character position for the 2-gram probability.
    * 
    * @param i - 2-gram index
    * @return cipher integer index
    */
    public int getCipher1Index(int i){
        return (int)((double)i/(double)cipherSetSize) % cipherSetSize;
    }
    
    /**
    *       calcEnergyEquiv calculates an energy equivalent based on decrypted
    *   probabilities being compared with measured plain alphabet probabilities
    *   for 2 character sets.
    * 
    * @param keyProb - decrypt key
    * @param tempprob - decrypt key prob
    * @return energy equiv 
    */
    public double calcSecondOrderE(ArrayList<Integer> temp, ArrayList<Double> tempprob){
        double e = 0;
        int startInd = plainSetSize;
        if(tempprob.size() < calcProbSize(plainSetSize, 2)){
            while(tempprob.size() < calcProbSize(plainSetSize, 2)){
                tempprob.add(0.0);
            }
        }else{
            for(int u = 0 ; u < plainSetSize*plainSetSize; u++ ){
                tempprob.set(u+startInd, 0.0);
            }
        }
        int let1;int let2;
        for(int u = 0 ; u < cipherSetSize*cipherSetSize; u++ ){
            let1 = getCipher1Index(u);
            let2 = getCipher2Index(u);
            tempprob.set(temp.get(let2)+plainSetSize*temp.get(let1), cipherProb.get(u+cipherSetSize));
        }
        startInd = plainSetSize;
        for(int u = 0 ; u < plainSetSize*plainSetSize; u++ ){
            e += plainProb.get(2*u+startInd)*tempprob.get(u+startInd);
        }
        return (-1.0*e*secondOrderContrib);
    }
    
    /**
    *       getPlainProb returns the plain probability
    * 
    * @return plain probability
    */
    public ArrayList<Double> getPlainProb(){
        return plainProb;
    }
    
    /**
    *       getCipherProb returns the cipher probability
    * 
    * @return cipher probability
    */
    public ArrayList<Double> getCipherProb(){
        return cipherProb;
    }
    
    /**
    *       getCipherCharSet returns the cipher character set.
    * 
    * @return cipher character set
    */
    public ArrayList<Character> getCipherCharSet(){
        return cipherSet;
    }
    
    /**
    *       getCipherPossSet returns the alphabet possible decryption set given a cipher value.
    * 
    * @return alphabet character set
    */
    public ArrayList<ArrayList<Integer>> getCipherPossSet(){
        return cipherPossSet;
    }
    
    /**
    *       getCipherPossSet returns the cipher possible decryption set given a plain value.
    * 
    * @return cipher possible character set
    */
    public ArrayList<ArrayList<Integer>> getCipherAlphSet(){
        return alphPossCipher;
    }

    /**
    *       getCipherBoundsSet returns the indices array for an array of possible decryptions.
    * 
    * @return character set indices
    */
    public ArrayList<Integer> getCipherBoundsSet(){
        return cipherBounds;
    }
    
    /**
    *       getAscendAlphSet returns an array with sets of possible decryptions 
    *   based on decreasing probability
    * 
    * @return possible character set
    */
    public ArrayList<ArrayList<Integer>> getAscendAlphSet(){
        return ascendingAlphSet;
    }
}