import time

def knows_how_to_generate(output_file, another_input_dep):
    f = open(output_file, "w")
    print >>f, "#define GENERATED \"%s\"" % (time.ctime(), )
    print >>f, "#define ANOTHER_GENERATED \"%s\"" % (open(another_input_dep).read().strip(), )
    f.close()
