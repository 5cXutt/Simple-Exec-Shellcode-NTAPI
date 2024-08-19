# Simple-Exec-Shellcode-NTAPI
## Tecniche da Integrare

### 1. Metamorphism
- **Descrizione**: Modifica dinamicamente il codice in fase di esecuzione per cambiare continuamente la sua struttura.
- **Esempio**: Virus metamorfici che modificano il proprio codice ogni volta che vengono infettati.
- **Stato**: Alla Fine (molto difficile)

### 2. ROP Chains (Return-Oriented Programming)
- **Descrizione**: Utilizza sequenze di istruzioni terminate da un `return` (chiamate "gadgets") per eseguire codice arbitrario.
- **Esempio**: Creare una catena di gadget che esegue operazioni specifiche in sequenza per bypassare le protezioni.
- **Stato**: Alla Fine (molto difficile)

### 3. Code Obfuscation
- **Descrizione**: Rende il codice sorgente o binario difficile da comprendere e analizzare.
- **Esempio**: 
  - **Renaming (Ridenominazione)**: Cambia i nomi delle variabili, funzioni, e classi in nomi non significativi o casuali.
  - **Control Flow Obfuscation**: Modifica il flusso di controllo del programma senza cambiarne il comportamento.
  - **Data Obfuscation**: Modifica i dati e le strutture di dati per rendere più difficile la comprensione.
  - **Dummy Code Insertion**: Inserisce codice che non ha alcun effetto sul programma ma aumenta la complessità.
  - **Polymorphism**: Modifica il codice in modo che ogni istanza del programma sia leggermente diversa.
- **Stato**: Alla Fine

### 4. Process Hollowing
- **Descrizione**: Tecnica per iniettare codice in un processo già esistente, sostituendo il contenuto della memoria del processo con il proprio codice.
- **Esempio**: Sostituire il contenuto della memoria di un processo legittimo con un payload malevolo.
- **Stato**: Da Implementare

### 5. Direct Kernel Object Manipulation (DKOM)
- **Descrizione**: Manipola direttamente le strutture di dati del kernel per alterare il comportamento del sistema operativo.
- **Esempio**: Modificare le strutture di dati del kernel per nascondere un processo.
- **Stato**: Da Implementare

### 6. Code Fragmentation
- **Descrizione**: Divide il codice in frammenti e li distribuisce in diverse parti del programma.
- **Esempio**: Spezzare il codice in segmenti e mescolarli in posizioni disparate per complicare l'analisi.
- **Stato**: Da Implementare

### 7. Direct Kernel Manipulation
- **Descrizione**: Manipola direttamente le strutture e le funzioni del kernel per ottenere controllo o nascondere attività.
- **Esempio**: Alterare i puntatori delle funzioni del kernel per eludere la rilevazione.
- **Stato**: Da Implementare

### 8. Spezzare Shellcode
- **Descrizione**: Dividere la shellcode in frammenti e mescolarli per rendere più difficile la rilevazione e l'esecuzione.
- **Esempio**: Suddividere la shellcode in blocchi e inserirli in modo casuale nel programma.
- **Stato**: Da Implementare
