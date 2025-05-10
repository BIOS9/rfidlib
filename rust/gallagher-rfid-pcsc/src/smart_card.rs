use pcsc::Card;

pub struct SmartCard {
    pcsc_card: Card
}

impl SmartCard {
    pub(crate) fn new(pcsc_card: Card) -> Self {
        SmartCard { pcsc_card }
    }

    pub fn read_uuid(&self) {
        
    } 
}