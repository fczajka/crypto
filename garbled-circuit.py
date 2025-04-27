import random
import hashlib
import sys

# ----------------------------------------------------------------------
# Funkcje narzędziowe do szyfrowania/deszyfrowania w garbled circuit.
# Symulujemy podwójne szyfrowanie za pomocą otp opartego na hashu.
# ----------------------------------------------------------------------

# Globalny licznik identyfikatorów bramek (do unikalnego oznaczania każdej bramki)
gate_id_counter = 0


def get_next_gate_id():
    global gate_id_counter
    gate_id = gate_id_counter
    gate_id_counter += 1
    return gate_id


def hash_value(k1, k2, gate_id):
    s = f"{k1}_{k2}_{gate_id}"
    h = hashlib.sha256(s.encode()).digest()
    return int.from_bytes(h, 'big')


# Szyfruj etykietę wyjściową przy użyciu kluczy dla dwóch wejść i identyfikatora bramki.
def encrypt(key1, key2, gate_id, out_label):
    pad = hash_value(key1, key2, gate_id)
    return out_label ^ pad


# Deszyfruj tekst zaszyfrowany przy użyciu kluczy dla dwóch wejść i identyfikatora bramki.
def decrypt(key1, key2, gate_id, ciphertext):
    pad = hash_value(key1, key2, gate_id)
    return ciphertext ^ pad


# Przewód: każdy przewód ma dwie losowe etykiety (jedną dla 0 i jedną dla 1) oraz, opcjonalnie, wyraźną wartość binarną.

class Wire:

    def __init__(self, name, value=None):
        self.name = name
        # Do symulacji wybieramy 64-bitowe losowe liczby całkowite jako etykiety.
        self.labels = {0: random.getrandbits(64), 1: random.getrandbits(64)}
        self.value = value  # Wyraźna wartość (jeśli znana)
        self.evaluated_label = None  # Będzie zawierać etykietę po ocenie bramki

    def set_value(self, value):
        self.value = value
        self.evaluated_label = self.labels[value]

    def get_bit_from_label(self, label):
        # Dla danej etykiety, zwraca odpowiadający jej wyraźny bit (0 lub 1)
        for bit, lab in self.labels.items():
            if lab == label:
                return bit
        return None


# Bramka: reprezentuje bramkę logiczną z dwoma wejściami.
# Tabela garbled dla bramki jest budowana poprzez szyfrowanie odpowiedniej etykiety przewodu wyjściowego dla każdej możliwej kombinacji wejść.

class Gate:

    def __init__(self,
                 input_wire1,
                 input_wire2,
                 output_wire,
                 func,
                 gate_type="generic"):
        self.input_wire1 = input_wire1
        self.input_wire2 = input_wire2
        self.output_wire = output_wire
        # Funkcja logiczna dla tej bramki (np. XOR, AND, OR)
        self.func = func
        # Unikalny identyfikator, używany w szyfrowaniu
        self.gate_id = get_next_gate_id()
        self.gate_type = gate_type
        self.garbled_table = []
        self._garble()

    def _garble(self):
        table = []
        # Dla każdej możliwej kombinacji wejść, obliczamy bit wyjściowy,
        # pobieramy odpowiadające klucze (etykiety) i szyfrujemy etykietę wyjściową.
        for a in [0, 1]:
            for b in [0, 1]:
                out_bit = self.func(a, b)
                key_a = self.input_wire1.labels[a]
                key_b = self.input_wire2.labels[b]
                out_label = self.output_wire.labels[out_bit]
                ciphertext = encrypt(key_a, key_b, self.gate_id, out_label)
                table.append(((a, b), ciphertext))
        # Permutujemy tabelę, aby ukryć kolejność.
        random.shuffle(table)
        self.garbled_table = [entry[1] for entry in table]

    def evaluate(self, label_a, label_b):
        # Ewaluator próbuje odszyfrować każdy tekst zaszyfrowany przy użyciu dostarczonych kluczy.
        for ciphertext in self.garbled_table:
            decrypted = decrypt(label_a, label_b, self.gate_id, ciphertext)
            # Sprawdzamy, czy deszyfrowanie daje jedną z poprawnych etykiet wyjściowych.
            if decrypted == self.output_wire.labels[
                    0] or decrypted == self.output_wire.labels[1]:
                self.output_wire.evaluated_label = decrypted
                return decrypted
        print(
            f"Błąd ewaluacji bramki {self.gate_id} (typ {self.gate_type}).",
            file=sys.stderr)
        return None


# Funkcje bramek logicznych
def xor_gate(a, b):
    return a ^ b


def and_gate(a, b):
    return a & b


def or_gate(a, b):
    return a | b


# ----------------------------------------------------------------------
# GarbledFullAdderCircuit buduje obwód który dodaje liczby 3-bitowe.
# Łączy niezbędne bramki aby obliczyć 4-bitową sumę, a następnie zwraca końcowy wynik uzyskany przez podzielenie sumy przez 2 (przesunięcie bitowe w prawo).
# ----------------------------------------------------------------------
class GarbledFullAdderCircuit:

    def __init__(self, a_bits, b_bits):
        # Upewnij się, że oba wejścia to 3-bitowe tablice (kolejność LSB)
        if len(a_bits) != 3 or len(b_bits) != 3:
            raise ValueError("Oba wejścia muszą być 3-bitowymi tablicami.")
        self.a_bits = a_bits
        self.b_bits = b_bits
        self.wires = {}
        self.gates = []
        self._build_circuit()

    def _new_wire(self, name, value=None):
        wire = Wire(name, value)
        self.wires[name] = wire
        if value is not None:
            wire.set_value(value)
        return wire

        # Tworzymy przewody wejściowe dla bitów A i B.
    def _build_circuit(self):
        a0 = self._new_wire('a0', self.a_bits[0])
        a1 = self._new_wire('a1', self.a_bits[1])
        a2 = self._new_wire('a2', self.a_bits[2])
        b0 = self._new_wire('b0', self.b_bits[0])
        b1 = self._new_wire('b1', self.b_bits[1])
        b2 = self._new_wire('b2', self.b_bits[2])

        # --- Dodawanie bitu 0 (LSB) ---
        # Bramka1: XOR dla sum0 = a0 XOR b0
        sum0 = self._new_wire('sum0')
        gate1 = Gate(a0, b0, sum0, xor_gate, "XOR")
        self.gates.append(gate1)
        # Bramka2: AND dla carry0 = a0 AND b0
        carry0 = self._new_wire('carry0')
        gate2 = Gate(a0, b0, carry0, and_gate, "AND")
        self.gates.append(gate2)

        # --- Dodawanie bitu 1 ---
        # Bramka3: XOR dla temp1 = a1 XOR b1
        temp1 = self._new_wire('temp1')
        gate3 = Gate(a1, b1, temp1, xor_gate, "XOR")
        self.gates.append(gate3)
        # Bramka4: XOR dla sum1 = temp1 XOR carry0
        sum1 = self._new_wire('sum1')
        gate4 = Gate(temp1, carry0, sum1, xor_gate, "XOR")
        self.gates.append(gate4)
        # Bramka5: AND dla and1 = a1 AND b1
        and1 = self._new_wire('and1')
        gate5 = Gate(a1, b1, and1, and_gate, "AND")
        self.gates.append(gate5)
        # Bramka6: AND dla and2 = temp1 AND carry0
        and2 = self._new_wire('and2')
        gate6 = Gate(temp1, carry0, and2, and_gate, "AND")
        self.gates.append(gate6)
        # Bramka7: OR dla carry1 = and1 OR and2
        carry1 = self._new_wire('carry1')
        gate7 = Gate(and1, and2, carry1, or_gate, "OR")
        self.gates.append(gate7)

        # --- Dodawanie bitu 2 ---
        # Bramka8: XOR dla temp2 = a2 XOR b2
        temp2 = self._new_wire('temp2')
        gate8 = Gate(a2, b2, temp2, xor_gate, "XOR")
        self.gates.append(gate8)
        # Bramka9: XOR dla sum2 = temp2 XOR carry1
        sum2 = self._new_wire('sum2')
        gate9 = Gate(temp2, carry1, sum2, xor_gate, "XOR")
        self.gates.append(gate9)
        # Bramka10: AND dla and3 = a2 AND b2
        and3 = self._new_wire('and3')
        gate10 = Gate(a2, b2, and3, and_gate, "AND")
        self.gates.append(gate10)
        # Bramka11: AND dla and4 = temp2 AND carry1
        and4 = self._new_wire('and4')
        gate11 = Gate(temp2, carry1, and4, and_gate, "AND")
        self.gates.append(gate11)
        # Bramka12: OR dla carry2 = and3 OR and4 (ostatnie przeniesienie)
        carry2 = self._new_wire('carry2')
        gate12 = Gate(and3, and4, carry2, or_gate, "OR")
        self.gates.append(gate12)

        # Pełna suma to 4-bitowy wynik: [sum0 (LSB), sum1, sum2, carry2 (MSB)]
        self.full_sum_wires = [sum0, sum1, sum2, carry2]
        # Końcowy wynik jest zdefiniowany jako pełna suma podzielona przez 2 (przesunięcie w prawo), tj. pominięcie LSB
        self.result_wires = [sum1, sum2, carry2]

    def evaluate(self):
        # Oceniamy każdą bramkę
        for gate in self.gates:
            label_a = gate.input_wire1.evaluated_label
            label_b = gate.input_wire2.evaluated_label
            if label_a is None or label_b is None:
                print(f"Błąd: Brakująca etykieta wejściowa dla bramki {gate.gate_id}",
                      file=sys.stderr)
                return
            gate.evaluate(label_a, label_b)
        # Konwertujemy ocenione etykiety wyjściowe z powrotem na wyraźne bity.
        output = []
        for wire in self.result_wires:
            bit = wire.get_bit_from_label(wire.evaluated_label)
            output.append(bit)
        print(output)
        return output

    def print_details(self):
        print("----- Zafałszowany Garbled Circuit - Full Adder -----")
        print("\nWartości Wejściowe (od LSB):")
        print("A:", self.a_bits)
        print("B:", self.b_bits)
        print("\nEtykiety Przewodów Wejściowych (dla wybranego bitu):")
        for name in ['a0', 'a1', 'a2', 'b0', 'b1', 'b2']:
            wire = self.wires[name]
            bit = wire.value
            label = wire.labels[bit]
            print(f"{name} (wartość={bit}): etykieta = {label}")
        print("\nTabela Garbled dla każdej bramki:")
        for gate in self.gates:
            print(
                f"ID bramki {gate.gate_id} Typ {gate.gate_type} "
                f"(Przewody wejściowe: {gate.input_wire1.name}, {gate.input_wire2.name}; "
                f"Przewód wyjściowy: {gate.output_wire.name})")
            for ct in gate.garbled_table:
                print("  Tekst zaszyfrowany:", ct)
        print("\nWynik (suma dodawania podzielona przez 2 (czyli bitowo przesunięta w prawo)):")
        full_sum = [
            wire.get_bit_from_label(wire.evaluated_label)
            for wire in self.full_sum_wires
        ]
        result = [
            wire.get_bit_from_label(wire.evaluated_label)
            for wire in self.result_wires
        ]
        print("Suma (od LSB):", full_sum)
        print("Końcowy Wynik (podzielony przez 2, od LSB):", result)


# ----------------------------------------------------------------------
# Demo: Budowa i ocena obwodu garbled  full adder

if __name__ == "__main__":
    # Dane wejściowe: 3-bitowe liczby binarne (od LSB do MSB)
    a_bits = [1, 0, 1] # Przykład: 5 (101 w binarnym)
    b_bits = [1, 0, 0] # Przykład: 1 (100 w binarnym)

    # Tworzymy obwód garbled.
    circuit = GarbledFullAdderCircuit(a_bits, b_bits)

    # Ewaluujemy obwód.
    result = circuit.evaluate()

    # Wyświetlamy szczegółowe informacje: wejścia, tabele garbled i wynik.
    circuit.print_details()

    # Dla łatwiejszego odczytu, obliczamy również jawne działanie arytmetyczne.
    def bits_to_int(bits):
        return sum(bit << i for i, bit in enumerate(bits))

    a_int = bits_to_int(a_bits)
    b_int = bits_to_int(b_bits)
    full_sum_bits = [
        wire.get_bit_from_label(wire.evaluated_label)
        for wire in circuit.full_sum_wires
    ]
    full_sum_int = bits_to_int(full_sum_bits)
    result_int = bits_to_int(result)

    print("\n----- Jawna Arytmetyka -----")
    print(f"A = {a_int} (binarnie: {a_bits[::-1]})")
    print(f"B = {b_int} (binarnie: {b_bits[::-1]})")
    print(f"Suma = {full_sum_int} (binarnie: {full_sum_bits[::-1]})")
    print(
        f"Końcowy Wynik (Suma / 2) = {result_int} (binarnie: {result[::-1]})"
    )
