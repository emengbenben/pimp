from powerball import PowerBall
from Roulette import Roulette

class Homepage():
  def start(self):
    self.status = "0" # the game's initial status is 0, 0 means the game is still on the homepage
    self.response = ""
    self.sign = False
  
  def getSign(self):
    return self.sign

  def setSign(self):
    self.sign = True

  def getstatus(self):
  	return self.status

  def input(self,string):
    #if self.status === 0, choose Service
    if self.status == "0":
      if string >="1" and string <= "6":
        self.response = self.choose_game(string)
      else:
        self.response = "Improper input."
    elif self.status == "1":
      self.response = self.powerball.input(string)

      if self.powerball.getquit() == True:
        self.status = "0"
        self.response = self.homepage()

    elif self.status == "2":
      self.response = self.roulette.input(string)
      
      if self.roulette.getquit() == True:
        self.status = "0"
        self.response = self.homepage()

    else:
      self.response = "Error!!!"

    return self.response
        
  
  def welcome_narratives(self):
    response = "Welcome to the Golden Nugget Casino!\n" 
    response = response +"WHERE FRIENDSHIP IS THE LARGEST JACKPOT!\n\n"
    response = response + "May we all be winners -> complete assignemnts, pass this course, get straight As, and an internship & job.\n"
    response = response + "Speaking of internships and jobs, we have an expert team here at Golden Nugget to assist with your career needs:\n"
    response = response + "-10 Bitpoints for resume review or cover letter review\n"
    response = response + "-100 bitpoints for writing your cover letter\n"
    response = response + "-250 bitpoints for internship/job referral\n\n"
    response = response + "Casino Services Menu:\n"
    response = response + "1. Powerball\n"
    response = response + "2. Roulette\n"
    response = response + "3. Career Assisstance # direct transfer with memo\n"
    response = response + "4. About Us\n"
    response = response + "5. Career with Golden Nugget Casino\n"
    response = response + "6. Quit\n\n"
    response = response + "Note: You can choose the menu by enter a single digit that is corresponding to the menu."

    return response
  
  def homepage(self):
    response = "1. Powerball\n"
    response = response + "2. Roulette\n"
    response = response + "3. Career Assisstance # direct transfer with memo\n"
    response = response + "4. About Us\n"
    response = response + "5. Career with Golden Nugget Casino\n"
    response = response + "6. Quit\n\n"
    response = response + "Note: You can choose the menu by enter a single digit that is corresponding to the menu."
    return response
      
  def choose_game(self, userInput):
    output = ""
    if userInput == "1":
        self.status = "1"
        lottery = [12, 24 ,35, 55, 22]
        self.powerball = PowerBall(1000, lottery)
        output = self.powerball.start()
    elif userInput == "2":
        self.status = "2"
        self.roulette = Roulette()
        output = self.roulette.start()
    elif userInput == "3":
        self.status = "0"
    elif userInput == "4":
        self.status = "0"
    elif userInput == "5":
        self.status = "0"
    elif userInput == "6":
        self.status = "6"
    else:
        output  = "Please enter a single digit of your choice."
    return output
