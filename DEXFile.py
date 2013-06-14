__author__ = 'weilun'

from struct import *
import zlib
import os
import hashlib

class DEXFile :
    ''' Read
    '''
    def __init__(self , filePath , verbose = False ):
        self.mFilePath = filePath
        self.mVerbose = verbose
        self.curPos = 0

        if filePath == None :
            raise Exception("Cannot open the a None file")

        if self.mVerbose :
            print "[+] lode file " ,  filePath

        self.mFile = open( filePath , "rb")
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

    def read(self , offset  , size,  fmt ):
        self.mFile.seek( offset  , 0 )
        data = self.mFile.read( size )
        if fmt != None :
            data = unpack( fmt , data )
        return data

    def toHexString( self , arr , reverse = False ):
        # Check if we can reverse the arr or not
        if reverse == True and len( arr ) % 4 != 0 :
            print "Only support the 4X size ( X is interger number ) "
            reverse = False

        if reverse :
            tmp = [ 0 for x in  arr ]
            for i in range( len( arr) / 4 )  :
                for j in range( 4 ) :
                    tmp[ i * 4  + j ] = arr[ i * 4 + 3 - j ]
            arr = tmp
        return '0x' + ''.join( '%02x' % byte for byte in arr )

    def get_header_information( self ):
        self.get_magic()
        self.get_checksum()
        self.get_signature()
        self.get_filesize()
        self.check_headersize()

    def get_magic(self):
        # Check the magic word
        magic = self.toHexString( self.read( 0 , 4 , 'BBBB'))
        if magic != '0x6465780a' :
            raise Exception("The magic word of the dex file is not right .Please Check!!")
        self.header['magic'] = magic
        #get the version of the dex file
        self.dex_type = self.toHexString(  self.read( 6 , 1 , 'B') )
        if self.dex_type == '0x35' :
            self.header['header_size'] = 112
        elif self.dex_type == '0x36' :
            self.header['header_size'] = 92
        if self.dex_type  != '0x35' and self.dex_type != '0x36' :
            raise Exception("The version of the dex file is not supported!!")
        self.header['magic_ver'] = self.dex_type

    def get_checksum(self):
        self.header['checknum'] = self.toHexString( self.read( 8 , 4 , 'BBBB') , True   )
        checksum  = int( self.header['checknum']  , 16 )
        checksum_cal =  zlib.adler32(  self.read( 12 , os.path.getsize(self.mFilePath ) * 4  - 12 , None  )) & 0xffffffff
        if checksum != checksum_cal :
            raise Exception("The checksum of the dex file is not right !! ")

    def get_signature(self ):
        self.header['signature'] = self.toHexString(  self.read( 12 ,  20 , 'BBBBBBBBBBBBBBBBBBBB' ) )
        cal_signature = hashlib.sha1( self.read( 32 , os.stat(self.mFilePath).st_size - 32 , None ) ).hexdigest()
        if '0x' + cal_signature != self.header['signature'] :
            raise Exception('The signature of the dexfile is broken !!!')

    def get_filesize(self):
        self.header['file_size'] = self.read(32 , 4 , 'I' )[0]
        if self.header['file_size'] != os.stat( self.mFilePath ).st_size :
            raise Exception('The file_size of the dexfile is not right !!!')

    def check_headersize(self):
        header_size = self.read( 36 , 4 , 'I')[0]
        if header_size!= self.header['header_size'] :
            raise Exception("Header size is not right !!!")




