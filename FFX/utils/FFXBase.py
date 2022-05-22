from abc import ABC, abstractmethod

class FFXBase(ABC):

    @abstractmethod
    def encrypt(data, key, tweak):
        pass
    
    @abstractmethod
    def decrypt(data, key, tweak):
        pass
    