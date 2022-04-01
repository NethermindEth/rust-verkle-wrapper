pub trait DB {
    fn create_db(path: &str) -> Self;
}

pub trait ReadOnlyDB {
    type DbObject;
    fn create_from_db(db: &'static mut Self::DbObject) -> Self;
    fn clear_temp_changes(&mut self);
}
