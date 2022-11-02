package me.synology.hajubal.springsecurity;

public class NewMain {
    public static void main(String[] args) {
        NewMain nm = new NewMain();
        nm.doit();
    }

    class A {
    }

    class B extends A {
    }

    public void doit() {
        A myA = new A();
        B myB = new B();
        A[] aArr = new A[0];
        B[] bArr = new B[0];

        System.out.println("b instanceof a: " + (myB instanceof A)); // true
        System.out.println("b isInstance a: " + A.class.isInstance(myB)); //true
        System.out.println("a isInstance b: " + B.class.isInstance(myA)); //false
        System.out.println("b isAssignableFrom a: " + A.class.isAssignableFrom(B.class)); //true
        System.out.println("a isAssignableFrom b: " + B.class.isAssignableFrom(A.class)); //false
        System.out.println("bArr isInstance A: " + A.class.isInstance(bArr)); //false
        System.out.println("bArr isInstance aArr: " + aArr.getClass().isInstance(bArr)); //true
        System.out.println("bArr isAssignableFrom aArr: " + aArr.getClass().isAssignableFrom(bArr.getClass())); //true
    }
}
