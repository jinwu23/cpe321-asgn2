import sys


def main():
    if len(sys.argv) != 2:
        print("Please input a single file")
        return
    
    output_file = open("output.txt", "w")
    for line in read_file(sys.argv[1]):
        output_file.write(line)

    return


def read_file(file_path):
    try:
        with open(file_path, "r") as file:
            lines = file.readlines()
            file.close()
            return lines
    except FileNotFoundError:
        print("File not found")
    except Exception:
        print("An error occured")
    return None

if __name__ == "__main__":
    main()