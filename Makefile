NAZWA = elgamal
$(NAZWA): $(NAZWA).o -lgmpxx -lgmp
	g++ -o $(NAZWA) $(NAZWA).o -lgmpxx -lgmp
$(NAZWA).o: $(NAZWA).cpp
	g++ -Wall -c -g $(NAZWA).cpp -lgmpxx -lgmp
clean:
	rm -f $(NAZWA) *.o