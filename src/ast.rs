//! Abstract Syntax Tree

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Span {
    pub line: u32,
    pub col:  u32,
}

impl Span {
    pub fn new(line: u32, col: u32) -> Self { Self { line, col } }
    pub fn is_unknown(self) -> bool { self.line == 0 && self.col == 0 }
}

impl std::fmt::Display for Span {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_unknown() { write!(f, "<unknown>") }
        else                 { write!(f, "{}:{}", self.line, self.col) }
    }
}

#[derive(Debug, Clone)]
pub enum Expr {
    Int(i64),
    Str(String),
    Bool(bool),
    Var(String),
    Assign { name: String, value: Box<Expr> },
    Unary  { op: String, operand: Box<Expr> },
    Binary { op: String, lhs: Box<Expr>, rhs: Box<Expr> },
    Call   { ns: String, fname: String, args: Vec<Expr>, span: Span },

    /// base.field - struct field read. base evaluates to the struct's
    /// address; the codegen offsets from it.
    Field        { base: Box<Expr>, field: String },
    /// base.field = value - struct field write.
    FieldAssign  { base: Box<Expr>, field: String, value: Box<Expr> },
    /// *ptr = value - assignment through a pointer. The width of the
    /// store is taken from the pointee type when knowable (e.g. ptr is a
    /// u32* local), otherwise defaults to qword.
    DerefAssign  { ptr: Box<Expr>, value: Box<Expr> },
    /// (type) expr - C-style cast. V1 is a no-op at the machine level
    /// (all scalars are 8-byte slots), kept as a syntactic marker so the
    /// future type checker can validate intent.
    Cast         { ty: String, expr: Box<Expr> },
    SizeOf       { ty: String },
    /// base[index] - indexed read. base is a pointer or array (T*
    /// or T[N]); the codegen multiplies index by sizeof to find
    /// the byte offset, then emits a width-correct load.
    Index        { base: Box<Expr>, index: Box<Expr> },
    /// base[index] = value - indexed write. Mirrors Index for stores.
    IndexAssign  { base: Box<Expr>, index: Box<Expr>, value: Box<Expr> },
    StructLit    { ty: String, fields: Vec<(String, Expr)>, span: Span },
}

#[derive(Debug, Clone)]
pub enum Stmt {
    Var     { name: String, ty: String, value: Option<Expr>, span: Span },
    Expr    { value: Expr, span: Span },
    If      { cond: Expr, then_body: Vec<Stmt>, else_body: Vec<Stmt> },
    While   { cond: Expr, body: Vec<Stmt> },
    For     {
        init: Option<Box<Stmt>>,
        cond: Option<Expr>,
        step: Option<Box<Stmt>>,
        body: Vec<Stmt>,
    },
    /// break; - exit the innermost enclosing for/while.
    Break,
    /// continue; - jump to the step (for) or condition (while) of the
    /// innermost enclosing loop.
    Continue,
    Ret     { value: Option<Expr>, span: Span },

    /// try { body } catch err { handler } - desugars to longjmp-style PIC.
    Try     { body: Vec<Stmt>, err_name: String, handler: Vec<Stmt> },

    /// raise expr; - longjmp-style unwind. Evaluates expr into rax,
    /// then jumps to the innermost installed try handler. With no
    /// handler installed, the program returns 0xFF.
    Raise   { value: Expr, span: Span },

    /// inline assembly: a sequence of parsed instructions plus raw bytes.
    Asm     (Vec<crate::asm::AsmLine>),
}

#[derive(Debug, Clone)]
pub struct Param { pub name: String, pub ty: String }

#[derive(Debug, Clone)]
pub struct Attr {
    pub kind: String,
    pub arg:  Option<String>,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub name:    String,
    pub params:  Vec<Param>,
    pub ret_ty:  String,
    pub body:    Vec<Stmt>,
    /// Function-level attributes parsed from [Attr] prefixes.
    /// Order is preserved.
    pub attrs:   Vec<Attr>,
    pub is_extern: bool,
}

#[derive(Debug, Clone)]
pub struct StaticDecl {
    pub name: String,
    pub ty:   String,
    pub init: Option<Expr>,
}

#[derive(Debug, Clone)]
pub struct StructDef {
    pub name:     String,
    pub fields:   Vec<(String, String)>, // (field name, type name)
    pub is_union: bool,
    pub attrs:    Vec<Attr>,
}

#[derive(Debug, Clone, Default)]
pub struct Program {
    pub structs:   Vec<StructDef>,
    pub statics:   Vec<StaticDecl>,
    pub functions: Vec<Function>,
    pub enums:     Vec<EnumDecl>,
}

#[derive(Debug, Clone)]
pub struct EnumDecl {
    pub name:     String,
    pub variants: Vec<(String, i64)>,
}
