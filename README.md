# AbsurdAgents_agents_Kshatriya
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![NumPy](https://img.shields.io/badge/numpy-%23013243.svg?style=for-the-badge&logo=numpy&logoColor=white)
![Pandas](https://img.shields.io/badge/pandas-%23150458.svg?style=for-the-badge&logo=pandas&logoColor=white)

## Usage 
Git clone the repository 
```bash
git clone https://github.com/rudradeep22/AbsurdAgents_agents_Kshatriya.git
```
change the working directory to the server
```
cd AbsurdAgents_agents_Kshatriya
```
Install python library all requirements
```bash
pip install -r requirements.txt
```
### For Hangman:
change working to hangman:
```shell
cd hangman
```
- `script.py` -> Is Agent for hangman
run it to play with server
```shell
python script.py
```
### For Schrödinger's cat:
change working to Schrodinger:
```shell
cd Schrodinger
```
- `script.py` -> Is Agent for Schrödinger's cat
run it to play with server
```shell
python script.py
```
### For Wordle , Evil Wordle and dordle :
- `parse_data.py` -> parse the raw data contained in data-raw and put it into data-parsed
- `possibilities_table.py` -> compute the possibilities matrix
- `solvewordle.py` -> Is an agent for Wordle. It playes on server
- `solvedordle.py` -> Is an agent for Dordle. It playes on server
- `solveevil.py` -> Is an agent for Evil Wordle. It playes on server

Run this to generate possibilities table
```shell
python parse_data.py
python possibilities_table.py
```
Then you can run the agents with:

for Wordle - 
```shell
python solvewordle.py
```
for Evil Wordle - 
```shell
python solveevil.py
```
for Dordle - 
```shell
python solvedordle.py
```






