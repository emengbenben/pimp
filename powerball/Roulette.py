import random

class Roulette:
	def __init__(self):
		self.betin = ""
		self.landon = random.randint(0, 36)
		self.LOB = []
		self.budget = 500
		self.valnum = -1
		self.valin = -1
		self.quit = False

	def getquit(self):
		return self.quit


	def betlist(self):
		response =  "\nThe Betting List:\n--------------------"
		response = response + "\nBet on it landing on an even number by typing 'even' "
		response = response + "\nBet on an odd number by typing 'odd' "
		response = response + "\nBet on it landing on a number between 0 and 12 by typing '1st 3rd' "
		response = response + "\nBet on it landing on a number between 13 and 25 by typing '2nd 3rd' "
		response = response + "\nBet on it landing on a number between 25 and 36 by typing '3rd 3rd' "
		response = response + "\nBet on it landing on a specific number by typing the 'betnum'"
		response = response + "\nType 'low' to bet between 0 (inclusive) and 18 (inclusive), and type 'high' to bet between 18 (exclusive) and 36 (inclusive) "
		response = response + "\nIf u want to quit this game, just input 'quit'"
		response = response + "\nPlace your bet: "
		return response

	def start(self):
		response = "Welcome to Roulette!"
		response = response + "The Betting List:\n--------------------"
		response = response + "\nBet on it landing on an even number by typing 'even' "
		response = response + "\nBet on an odd number by typing 'odd' "
		response = response + "\nBet on it landing on a number between 0 and 12 by typing '1st 3rd' "
		response = response + "\nBet on it landing on a number between 13 and 25 by typing '2nd 3rd' "
		response = response + "\nBet on it landing on a number between 25 and 36 by typing '3rd 3rd' "
		response = response + "\nBet on it landing on a specific number by typing the 'betnum'"
		response = response + "\nType 'low' to bet between 0 (inclusive) and 18 (inclusive), and type 'high' to bet between 18 (exclusive) and 36 (inclusive) "
		response = response + "\nIf u want to quit this game, just input 'quit'"
		response = response + "\nPlace your bet: "
		return response
	def roll(self):
		response = "\nSpinning..."
		self.landon = random.randint(0, 36)
		response = response + "It landed on " + str(self.landon) + "\n"
		
		return response

	def lose(self):
		response = "Oh no! You lost!"
		response = response + "You lost " + str(self.valin) + "dollars"
		self.budget -= self.valin
		response = response + "Your budget is now "+ str(self.budget)

		return response

	def evenwin(self):
		if(self.landon % 2 == 0):
			response = "Wow! You won! It was an even number!\n"
			response = response + "You receive "+ str(self.valin*2)+ " dollars!\n"
			self.budget += self.valin*2
			response = response +  "Your budget is now " + str(self.budget)
		else:
			response = self.lose()

		self.valnum = -1
		self.valin = -1
		self.betin = ""

		response = response + self.betlist()
		return response

	def oddwin(self):

		if(self.landon % 2 == 1):
			response = "Wow! You won! It was an odd number!\n"
			response = response + "You receive "+ str(self.valin*2)+ " dollars!\n"
			self.budget += self.valin*2
			response = response +  "Your budget is now " + str(self.budget)
		else:
			response = self.lose()

		self.valnum = -1
		self.valin = -1
		self.betin = ""

		response = response + self.betlist()
		return response

	def win13(self):
		if self.landon < 13:
			response = "Holy Cow! You won!"
			response = response + "You receive" + str(self.valin*3)+ " dollars!\n"
			self.budget += self.valin*3
			response = response +  "Your budget is now " + str(self.budget)
		else:
			response = self.lose()

		self.valnum = -1
		self.valin = -1
		self.betin = ""

		response = response + self.betlist()
		return response

	def win23(self):
		if  self.landon >= 13 and self.landon <= 25:
			response ="Oh yeah!!! Hit the jackpot!"
			response = response + "You receive " + str(self.valin*3)+ " dollars!\n"
			self.budget += self.valin*3
			response = response +  "Your budget is now " + str(self.budget)
		else:
			response = self.lose()

		self.valnum = -1
		self.valin = -1
		self.betin = ""

		response = response + self.betlist()
		return response

	def win33(self):
		if self.landon > 25:
			response = "Nice job...You got a number in the 3rd third! You won!"
			response = response + "You receive " + str(self.valin*3)+ " dollars!\n"
			self.budget += self.valin*3
			response = response +  "Your budget is now " + str(self.budget)
		else:
			response = self.lose()

		self.valnum = -1
		self.valin = -1
		self.betin = ""

		response = response + self.betlist()
		return response
	
	def numwin(self):
		if self.landon == self.valnum:
			response = "You won! You won! You won! "+ "Congratulations!\n"
			response = response + "You receive " + str(self.valin*36)+ " dollars!\n"
			self.budget += self.valin*36
			response = response +  "Your budget is now " + str(self.budget)
		else:
			response = self.lose()

		self.valnum = -1
		self.valin = -1
		self.betin = ""

		response = response + self.betlist()
		return response	

	def lowwin(self):
		if self.landon <= 18:
			response = "Nice, you won!\n"
			response = response + "You receive " + str(self.valin*2)+ " dollars!\n"
			self.budget += self.valin*2
			response = response +  "Your budget is now " + str(self.budget)
		else:
			response = self.lose()

		self.valnum = -1
		self.valin = -1
		self.betin = ""

		response = response + self.betlist()
		return response	
				
	def highwin(self):
		if self.landon > 18:
			response = "Nice, you won!\n"
			response = response + "You receive " + str(self.valin*2)+ " dollars!\n"
			self.budget += self.valin*2
			response = response +  "Your budget is now " + str(self.budget)
		else:
			response = self.lose()

		self.valnum = -1
		self.valin = -1
		self.betin = ""

		response = response + self.betlist()
		return response
				

	def input(self,input):	
		if(self.betin == "" and input.isdigit() == False):
			self.betin = input

		if input == 'quit':
			self.quit = True


		response = ""
		if self.betin == 'even':
			response = "You have chosen to bet on the even numbers"
			response = response + "\nHow much would you like to bet?: "

			if self.valin == -1 and input.isdigit():
				self.valin = int(input)
				response = "If it lands on an even number, you win " + str(self.valin*2)
				response = response + self.roll()
				response = response + self.evenwin()
				#LOB.append('beteven')
				
		elif self.betin == 'odd':
			response = "You have chosen to bet on the odd numbers"
			response = response + "\nHow much would you like to bet?: "
			if self.valin == -1 and input.isdigit():
				self.valin = int(input)
				response = "If it lands on an odd number, you win " + str(self.valin*2)
				response = response + self.roll()
				response = response + self.oddwin()
				#LOB.append('betodd')

				
		elif self.betin == '1st 3rd':
			response = "You have chosen to bet on numbers between 0 and 12"
			response = response + "\nHow much would you like to bet?: "

			if self.valin == -1 and input.isdigit():
				self.valin = int(input)
				response = "If it lands on the numbers between 0 and 12, you win " + str(self.valin*3)
				response = response + self.roll()
				response = response + self.win13()

		elif self.betin == '2nd 3rd':
			response = "You have chosen to bet on numbers between 13 and 25"
			response = response + "\nHow much would you like to bet?: "
			
			if input.isdigit():
				self.valin = int(input)
				response = "If it lands on the numbers between 13 and 25, you win " + str(self.valin*3)
				response = response + self.roll()
				response = response + self.win23()

		elif self.betin == '3rd 3rd':
			response = "You have chosen to bet on numbers between 25 and 36"
			response = response + "\nHow much would you like to bet?: "

			if input.isdigit():
				self.valin = int(input)
				response = "If it lands on the numbers between 25 and 36, you win " + str(self.valin*3)
				response = response + self.roll()
				response = response + self.win33()

		
		elif self.betin == 'betnum':

				response = "You have chosen to bet on a specific number"
				response = response + "\n What number would you like to bet on?: "

				if input.isdigit():
					if(self.valnum == -1 ):
						self.valnum = int(input)
					else:
						self.valin = -2
					if self.valnum > 36 or self.valnum < 0:
						response = "You can't bet that number..."
						response = response + "The file has reached an error, why did you do that?"
					else:
						response = "You chose to bet on" + str(self.valnum)
						response = response + "How much would you like to bet?: "

						if(self.valin == -2 and self.valnum != -1):
							self.valin = int(input)
							response = "If it lands on" + str(self.valnum) + "you win" + str(self.valin*36)
							response = response + self.roll()
							response = response + self.numwin()
		elif self.betin == 'low':
			response = "You chose to bet low"
			response = response + "\nHow much would you like to bet?: "

			if input.isdigit():
				self.valin = int(input)
				response = "If it lands on the 1st half of numbers, you win " + str(self.valin*2)
				response = response + self.roll()
				response = response + self.lowwin()

		elif self.betin == 'high':
			response = "You chose to bet high"
			response = response + "\nHow much would you like to bet?: "

			if input.isdigit():
				self.valin = int(input)
				response = "If it lands on the 2nd half of numbers, you win " + str(self.valin*2)
				response = response + self.roll()
				response = response + self.highwin()
		else:
			response = "Improper input!!!\n"
			response = response + self.betlist() 
			return response

		return response

"""
def main():
	roll = Roulette()
	print(roll.start())
	
	while True:
		command = input()
		output = roll.input(command)
		print(output)
            
if __name__=="__main__":
	main()
"""






