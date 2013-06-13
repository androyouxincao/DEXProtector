__author__ = 'weilun'

import struct

class DEXFile :


    def __init__(self , filePath , verbose = False ):
        self.mFilePath = filePath
        self.mVerbose = verbose

        if filePath == None :
            raise Exception("Cannot open the a None file")

        if self.mVerbose :
            print "[+] lode file " + filePath

        self.mFile = open( filePath , "rb")
        self.dex_type = None
        self.dex_ver = None

        self.header = {
            'magic' : None ,
            'magic_ver' : None ,
            'checknum' : None  ,
            'signature' : None ,
            'file_size' : None ,
            'header_size' : None ,
            'endian_tag' : None ,

            'link_size'  : None ,
            'link_offset' : None ,

            'map_offset' : None ,
            'type_ids_size' : None ,
            'type_ids_offset' : None ,
            'proto_ids_size' : None ,
            'proto_ids_offset' : None ,
            'filed_ids_size' : None ,
            'filed_ids_offset' : None ,
            'method_ids_size' : None ,
            'method_ids_offset' : None ,
            'class_defs_size' : None ,
            'class_defs_offset' : None ,
            'data_size' : None ,
            'data_offset' : None
        }

        self.get_header_information()

    def read(self , offset , size,  unpack ):
        pass

    def get_header_information( self ):
        print "Get header information"
        pass






