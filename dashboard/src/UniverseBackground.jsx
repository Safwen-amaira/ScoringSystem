import { useRef, useMemo } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { Stars, Float } from "@react-three/drei";

function ParticleField({ count = 2000 }) {
  const mesh = useRef();
  const positions = useMemo(() => {
    const pos = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      pos[i * 3] = (Math.random() - 0.5) * 100;
      pos[i * 3 + 1] = (Math.random() - 0.5) * 100;
      pos[i * 3 + 2] = (Math.random() - 0.5) * 100;
    }
    return pos;
  }, [count]);

  useFrame((state) => {
    if (mesh.current) {
      mesh.current.rotation.y = state.clock.elapsedTime * 0.02;
      mesh.current.rotation.x = Math.sin(state.clock.elapsedTime * 0.01) * 0.1;
    }
  });

  return (
    <points ref={mesh}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" count={count} array={positions} itemSize={3} />
      </bufferGeometry>
      <pointsMaterial size={0.15} color="#d4af37" transparent opacity={0.8} sizeAttenuation />
    </points>
  );
}

function GoldenNebula() {
  const mesh = useRef();
  
  useFrame((state) => {
    if (mesh.current) {
      mesh.current.rotation.z = state.clock.elapsedTime * 0.05;
    }
  });

  return (
    <Float speed={0.5} rotationIntensity={0.3} floatIntensity={0.5}>
      <mesh ref={mesh} position={[0, 0, -20]}>
        <sphereGeometry args={[15, 32, 32]} />
        <meshStandardMaterial 
          color="#1a0f00" 
          emissive="#d4af37" 
          emissiveIntensity={0.1}
          transparent 
          opacity={0.3}
        />
      </mesh>
    </Float>
  );
}

function OrbitingRings() {
  const group = useRef();
  
  useFrame((state) => {
    if (group.current) {
      group.current.rotation.x = Math.sin(state.clock.elapsedTime * 0.1) * 0.3;
      group.current.rotation.y = state.clock.elapsedTime * 0.15;
    }
  });

  return (
    <group ref={group}>
      {[0, 1, 2].map((i) => (
        <mesh key={i} rotation={[Math.PI / 3 * i, 0, 0]}>
          <torusGeometry args={[8 + i * 3, 0.02, 16, 100]} />
          <meshStandardMaterial 
            color="#d4af37" 
            emissive="#d4af37" 
            emissiveIntensity={0.5 - i * 0.15}
            transparent 
            opacity={0.6 - i * 0.15}
          />
        </mesh>
      ))}
    </group>
  );
}

export default function UniverseBackground() {
  return (
    <div className="universe-canvas">
      <Canvas camera={{ position: [0, 0, 30], fov: 75 }}>
        <ambientLight intensity={0.1} />
        <pointLight position={[10, 10, 10]} intensity={0.5} color="#d4af37" />
        <pointLight position={[-10, -10, -10]} intensity={0.3} color="#ff6b35" />
        
        <Stars 
          radius={100} 
          depth={50} 
          count={5000} 
          factor={4} 
          saturation={0.5} 
          fade 
          speed={1}
        />
        
        <ParticleField count={3000} />
        <GoldenNebula />
        <OrbitingRings />
        
        <fog attach="fog" args={["#0a0a0a", 20, 80]} />
      </Canvas>
    </div>
  );
}